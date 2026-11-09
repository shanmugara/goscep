// Copy buttons and click-to-select for the certificate pane. Served from /static so it
// passes the page's Content-Security-Policy (no inline scripts).
(function () {
  function selectAll(el) {
    el.focus();
    el.select();
    el.setSelectionRange(0, el.value.length);
  }

  function flash(button, text) {
    var original = button.dataset.label || button.textContent;
    button.dataset.label = original;
    button.textContent = text;
    clearTimeout(button._timer);
    button._timer = setTimeout(function () { button.textContent = original; }, 2000);
  }

  document.querySelectorAll("[data-copy]").forEach(function (button) {
    var target = document.getElementById(button.dataset.copy);
    if (!target) return;
    button.hidden = false;
    button.addEventListener("click", function () {
      var text = target.value;
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(
          function () { flash(button, "Copied"); },
          function () { selectAll(target); flash(button, "Press Ctrl/⌘+C"); }
        );
        return;
      }
      selectAll(target);
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      flash(button, ok ? "Copied" : "Press Ctrl/⌘+C");
    });
  });

  document.querySelectorAll("[data-select-all]").forEach(function (el) {
    el.addEventListener("focus", function () { selectAll(el); });
    el.addEventListener("mouseup", function (e) { e.preventDefault(); });
  });
})();
