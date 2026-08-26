// Auto-saves each viewer's own private Notes/Priority fields on the list-view
// tabs (see PersonalRecordInfo in models.py / save_personal_info() in app.py).
// These are personal to the logged-in user only - never shared with anyone
// else viewing the same escalation.
document.addEventListener("DOMContentLoaded", function () {
  function save(escId, notes, priority) {
    var body = new URLSearchParams();
    if (notes !== undefined) body.set("notes", notes);
    if (priority !== undefined) body.set("priority", priority);
    fetch("/escalations/" + escId + "/personal-info", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    }).catch(function () {});
  }

  document.querySelectorAll("[data-personal-notes]").forEach(function (input) {
    var escId = input.getAttribute("data-escalation-id");
    var priorityField = document.querySelector(
      '[data-personal-priority][data-escalation-id="' + escId + '"]'
    );
    input.addEventListener("click", function (e) { e.stopPropagation(); });
    input.addEventListener("blur", function () {
      save(escId, input.value, priorityField ? priorityField.value : undefined);
    });
  });

  document.querySelectorAll("[data-personal-priority]").forEach(function (select) {
    var escId = select.getAttribute("data-escalation-id");
    var notesField = document.querySelector(
      '[data-personal-notes][data-escalation-id="' + escId + '"]'
    );
    select.addEventListener("click", function (e) { e.stopPropagation(); });
    select.addEventListener("change", function () {
      save(escId, notesField ? notesField.value : undefined, select.value);
    });
  });
});
