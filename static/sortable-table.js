// Generic click-to-sort for list-view tables. Add data-sortable to a
// <table>. Each sortable <th> needs data-sort="text" or data-sort="num"
// PLUS data-key="somekey" matching the data-key="somekey" attribute on the
// corresponding <td> in every row - columns are matched by this key, not by
// position, so a table is safe to sort correctly even if some rows render a
// different number of conditional columns than others. Optionally give a
// <td> a data-sort-value="..." attribute to sort on something other than
// its visible text (e.g. a raw id/priority number instead of "#12" or "-").
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("table[data-sortable]").forEach(function (table) {
    var tbody = table.querySelector("tbody");
    if (!tbody) return;
    var headers = Array.prototype.slice.call(table.querySelectorAll("th[data-sort]"));
    headers.forEach(function (th) {
      if (!th.dataset.label) th.dataset.label = th.textContent.trim();
      var key = th.getAttribute("data-key");
      th.style.cursor = "pointer";
      th.title = "Click to sort";
      th.addEventListener("click", function () {
        var type = th.getAttribute("data-sort");
        var asc = th.getAttribute("data-asc") !== "true";
        headers.forEach(function (h) {
          h.removeAttribute("data-asc");
          h.textContent = h.dataset.label;
        });
        th.setAttribute("data-asc", asc ? "true" : "false");
        th.textContent = th.dataset.label + (asc ? " ▲" : " ▼");

        var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr")).filter(function (r) {
          return !r.classList.contains("empty-row");
        });
        rows.sort(function (a, b) {
          var aCell = key ? a.querySelector('[data-key="' + key + '"]') : null;
          var bCell = key ? b.querySelector('[data-key="' + key + '"]') : null;
          var av = aCell ? (aCell.getAttribute("data-sort-value") || aCell.textContent.trim()) : "";
          var bv = bCell ? (bCell.getAttribute("data-sort-value") || bCell.textContent.trim()) : "";
          if (type === "num") {
            av = parseFloat(av);
            bv = parseFloat(bv);
            if (isNaN(av)) av = asc ? Infinity : -Infinity;
            if (isNaN(bv)) bv = asc ? Infinity : -Infinity;
            return asc ? av - bv : bv - av;
          }
          av = String(av).toLowerCase();
          bv = String(bv).toLowerCase();
          if (av < bv) return asc ? -1 : 1;
          if (av > bv) return asc ? 1 : -1;
          return 0;
        });
        rows.forEach(function (r) {
          tbody.appendChild(r);
        });
      });
    });
  });
});
