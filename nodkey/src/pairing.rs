//! Pairing (docs/agent-protocol.md, "Pairing and the check number"): the code, the grant with the
//! phone's commitment, the pairing check, and the person's confirmation that both screens show the
//! same number. A phone is saved only after that confirmation; until then it waits in
//! `pairing.json` in the profile's folder, so the MCP server can ask in a separate call.

use nodkey_proto::{
    AgentInfo, Purpose, check,
    client::{self, AnswerFrom},
    code,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    agent::{Agent, Progress, Text, poll_until, text},
    mcp::opt_str,
    relay::{Relay, Signer},
    store::{Phone, Store},
};

/// The pairing that waits for the person's confirmation.
const PENDING: &str = "pairing.json";
/// How long it waits, in seconds.
const PENDING_FOR: u64 = 600;

#[derive(Serialize, Deserialize)]
struct Pending {
    /// The canonical code.
    code: String,
    phone: Phone,
    /// Unix time after which the pairing is no longer saved.
    until: u64,
}

fn err(msg: impl std::fmt::Display) -> String {
    msg.to_string()
}

impl Agent {
    /// The `pair` tool: without `code` it starts, with `code` it waits for the phone, and with
    /// `code` and `confirm` it saves the phone (or not).
    pub async fn pair_tool(
        &self,
        args: &serde_json::Map<String, serde_json::Value>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        let code = opt_str(args, "code")?;
        match (code, args.get("confirm").filter(|v| !v.is_null())) {
            (None, None) => self.pair_start(opt_str(args, "name")?).await,
            (None, Some(_)) => Err("confirm needs the code of the pairing".into()),
            (Some(code), None) => self.pair_finish(code, progress).await,
            (Some(code), Some(serde_json::Value::Bool(same))) => {
                self.pair_confirm(code, *same).await
            }
            (Some(_), Some(_)) => Err("confirm must be true or false".into()),
        }
    }

    /// Starts a pairing and returns the code to type on the phone.
    pub async fn pair_start(&self, name: Option<&str>) -> Result<Text, String> {
        let store = self.store()?;
        let relay = self.relay()?;
        let name = name.map(str::trim).filter(|n| !n.is_empty());
        if name.is_some_and(|n| n.chars().count() > 64) {
            return Err("name is too long (at most 64 characters)".into());
        }
        let id = store
            .identity_or_create(&self.default_name(), name)
            .map_err(err)?;
        let public = id.keys.public();
        let info = AgentInfo {
            agent_id: id.agent_id.clone(),
            name: id.name.clone(),
            sign: public.sign_b64u(),
            kem: public.kem_b64u(),
        };
        let signer = Signer {
            id: &id.agent_id,
            keys: &id.keys,
        };
        let pc = relay.start_pairing(&signer, &info).await.map_err(err)?;
        if !code::is_canonical(&pc.code) {
            return Err(format!(
                "relay returned an invalid pairing code {:?}",
                pc.code
            ));
        }
        clear_pending(&store);
        let shown = code::display(&pc.code);
        let expires_in = pc.expires.saturating_sub(nodkey_proto::unix_now());
        Ok(text(&json!({
            "code": shown,
            "agent_name": id.name,
            "expires": pc.expires,
            "expires_in_seconds": expires_in,
            "next": format!(
                "Show the user the code {shown} and ask them to type it in Nodkey on their iPhone under Agents. \
                 Then call pair again with code \"{shown}\" to wait for their phone and get the check number."
            ),
        })))
    }

    /// Waits for the phone to claim `code`, runs the pairing check and keeps the phone until the
    /// person confirms the check number ([`Agent::pair_confirm`]).
    pub async fn pair_finish(&self, typed: &str, progress: Progress<'_>) -> Result<Text, String> {
        let store = self.store()?;
        let relay = self.relay()?;
        let code = code::normalize(typed).map_err(err)?;
        let id = store
            .identity()
            .map_err(err)?
            .ok_or("No pairing was started on this computer. Call pair without a code first.")?;
        let signer = Signer {
            id: &id.agent_id,
            keys: &id.keys,
        };
        let total = self.timing.pairing;
        let claimed = poll_until(total, self.timing.max_wait, progress, "Waiting for the user to type the code on their iPhone", |wait| {
            relay.wait_pairing(&signer, &code, wait)
        })
        .await?
        .ok_or_else(|| {
            format!(
                "The code {} expired or was not claimed within {} s. Call pair without a code to get a new one.",
                code::display(&code),
                total.as_secs()
            )
        })?;
        nodkey_proto::validate_id(&claimed.phone_id)
            .map_err(|e| format!("relay sent a bad phone_id: {e}"))?;
        let phone_keys = nodkey_proto::PublicKeys::from_b64u(&claimed.sign, &claimed.kem)
            .map_err(|e| format!("relay sent bad phone keys: {e}"))?;

        // From here on, a pairing that cannot finish is left at the relay, so the phone drops it.
        let stop = |why: String| {
            let (signer, phone_id) = (&signer, &claimed.phone_id);
            async move {
                let _ = relay.leave(signer, phone_id).await;
                Err::<Text, String>(format!("{why} The pairing was not saved."))
            }
        };
        let Ok(plain) = Purpose::Pairing.open_box(
            id.keys.kem_secret(),
            &claimed.sealed(),
            &client::grant_aad(&code, &claimed.phone_id),
        ) else {
            return stop("The pairing grant does not decrypt.".into()).await;
        };
        let grant = match nodkey_proto::pairing::read_grant(&plain) {
            Ok(g) => g,
            Err(nodkey_proto::Error::OldApp) => {
                return stop(
                    "Nodkey on the iPhone is too old to pair with this version of nodkey. Update Nodkey \
                     from the App Store, then pair again."
                        .into(),
                )
                .await;
            }
            Err(e) => return stop(format!("{e}.")).await,
        };

        let agent_nonce = nodkey_proto::pairing::nonce();
        let request =
            nodkey_proto::pairing::check_request(&id.name, &agent_nonce, nodkey_proto::unix_now());
        let envelope = client::seal_request(
            &request,
            &id.agent_id,
            &claimed.phone_id,
            &phone_keys.kem,
            &id.keys.signing_key(),
            false,
        )
        .map_err(err)?;
        if let Err(e) = relay
            .post_request(&signer, &claimed.phone_id, &envelope)
            .await
        {
            return stop(format!("The pairing check could not be sent ({e}).")).await;
        }
        let answer_box = poll_until(
            self.timing.request,
            self.timing.max_wait,
            progress,
            "Waiting for the iPhone's pairing check",
            |wait| relay.wait_answer(&signer, &request.request_id, wait),
        )
        .await;
        let Ok(Some(answer_box)) = answer_box else {
            return stop("The iPhone did not answer the pairing check in time.".into()).await;
        };
        let from = AnswerFrom {
            agent_id: &id.agent_id,
            phone_id: &claimed.phone_id,
            sign: &phone_keys.sign,
            signs: true,
        };
        let number = Purpose::Answer
            .open_box(
                id.keys.kem_secret(),
                &answer_box,
                &client::answer_aad(&request.request_id, &claimed.phone_id),
            )
            .map_err(err)
            .and_then(|plain| client::read_answer(&plain, &request.request_id, &from).map_err(err))
            .and_then(|(answer, _)| {
                nodkey_proto::pairing::finish(
                    &answer,
                    &grant,
                    &id.keys.public(),
                    &phone_keys,
                    &agent_nonce,
                )
                .map_err(err)
            });
        let number = match number {
            Ok(n) => n,
            Err(e) => {
                return stop(format!(
                    "The iPhone's pairing check does not fit ({e}); the pairing messages may have been \
                     changed on the way."
                ))
                .await;
            }
        };

        let phone = Phone {
            phone_id: claimed.phone_id.clone(),
            name: grant.phone_name.clone(),
            sign: claimed.sign.clone(),
            kem: claimed.kem.clone(),
            check: check::digits(number),
            scope: grant.scope,
            paired_at: nodkey_proto::unix_now(),
            signs: true,
        };
        save_pending(
            &store,
            &Pending {
                code: code.clone(),
                phone,
                until: nodkey_proto::unix_now() + PENDING_FOR,
            },
        )?;
        let shown = check::display(number);
        Ok(text(&json!({
            "paired": false,
            "confirmed": false,
            "phone": grant.phone_name,
            "phone_id": claimed.phone_id,
            "check": shown,
            "scope": grant.scope,
            "next": format!(
                "Show the user the check number {shown} and ask whether Nodkey on their iPhone shows the same number. \
                 Only when they say it is the same, call pair with code \"{}\" and confirm: true; the pairing is \
                 saved then. If it is not the same, call pair with that code and confirm: false.",
                code::display(&code)
            ),
        })))
    }

    /// Saves the phone of the pairing that waits for `code` when the person says both screens
    /// show the same number (`same`); otherwise leaves it at the relay and saves nothing.
    pub async fn pair_confirm(&self, typed: &str, same: bool) -> Result<Text, String> {
        let store = self.store()?;
        let code = code::normalize(typed).map_err(err)?;
        let pending = read_pending(&store)?
            .filter(|p| p.code == code)
            .ok_or_else(|| {
                format!(
                    "No pairing with the code {} waits for a confirmation. Call pair without a code to start again.",
                    code::display(&code)
                )
            })?;
        clear_pending(&store);
        let late = nodkey_proto::unix_now() > pending.until;
        if !same || late {
            let left = self.leave_pending(&store, &pending.phone.phone_id).await;
            if late {
                return Err(format!(
                    "The check number was confirmed too late (after {} minutes). The pairing was not saved; \
                     pair again.",
                    PENDING_FOR / 60
                ));
            }
            return Ok(text(&json!({
                "paired": false,
                "phone": pending.phone.name,
                "relay_told": left,
                "next": "The numbers were not the same, so the pairing was not saved. Ask the user to cancel the \
                         pairing on their iPhone too. The pairing messages may have been changed on the way; \
                         they can try again, for example on another network.",
            })));
        }
        let phone = pending.phone;
        store.add_phone(phone.clone()).map_err(err)?;
        Ok(text(&json!({
            "paired": true,
            "phone": phone.name,
            "phone_id": phone.phone_id,
            "check": check::display(phone.check.parse().unwrap_or(0)),
            "scope": phone.scope,
            "next": "Paired. If the user has not confirmed the number on their iPhone yet, ask them to do that too.",
        })))
    }

    async fn leave_pending(&self, store: &Store, phone_id: &str) -> bool {
        let (Ok(Some(id)), Ok(relay)) = (store.identity(), self.relay()) else {
            return false;
        };
        let signer = Signer {
            id: &id.agent_id,
            keys: &id.keys,
        };
        Relay::leave(relay, &signer, phone_id).await.is_ok()
    }
}

fn clear_pending(store: &Store) {
    let _ = std::fs::remove_file(store.dir().join(PENDING));
}

fn save_pending(store: &Store, p: &Pending) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(p).expect("serializable");
    store.write(PENDING, &bytes, false).map_err(err)
}

fn read_pending(store: &Store) -> Result<Option<Pending>, String> {
    match store.read(PENDING).map_err(err)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("{PENDING}: {e}")),
        None => Ok(None),
    }
}
