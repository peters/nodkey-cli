//! Save vectors: a browser asks the phone to keep a login (the password sealed on its own), and
//! the phone's answer.

use super::{Ctx, Side, label_id, request, to_json};
use crate::{Answer, Decision, Kind, Purpose};

pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) {
    // Save: a browser asks the phone to keep a login, and the phone's answer. Sealed after the
    // others so their bytes stay the same.
    let rid_save = label_id("nodkey/v1/vectors/request/save");
    let mut r_save = request(
        &rid_save,
        Kind::Save,
        "vg.no",
        "Save the login you just used on vg.no",
        None,
    );
    let password_box = ctx.seal(
        "save_password",
        Purpose::Password,
        "agent",
        phone,
        agent.id.clone(),
        b"correct horse battery staple",
        false,
    );
    r_save.save = Some(crate::SaveLogin {
        url: "https://www.vg.no/login".into(),
        username: "alex@example.com".into(),
        password: password_box,
        title: Some("VG".into()),
    });
    ctx.seal(
        "request_save",
        Purpose::Request,
        "agent",
        phone,
        format!("{rid_save}{}", agent.id),
        &to_json(&r_save),
        true,
    );
    let mut a_save = Answer::decision(&rid_save, Decision::Approved);
    a_save.saved = Some(crate::Saved::Updated);
    ctx.seal(
        "answer_save",
        Purpose::Answer,
        "phone",
        agent,
        format!("{rid_save}{}", phone.id),
        &to_json(&a_save),
        true,
    );
}
