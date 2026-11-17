// Form helpers: matching password check, and no double submits.
(function () {
  document.querySelectorAll('form').forEach(function (form) {
    var pw = form.querySelector('input[name="new_password"]'), confirm = form.querySelector('input[name="confirm"]');
    if (pw && confirm) {
      var match = function () { confirm.setCustomValidity(confirm.value && confirm.value !== pw.value ? 'The two passwords don’t match.' : ''); };
      pw.addEventListener('input', match); confirm.addEventListener('input', match);
    }
    form.addEventListener('submit', function (e) {
      if (form.method.toLowerCase() !== 'post' || e.defaultPrevented) return;
      var btn = e.submitter || form.querySelector('button:not([type="button"])');
      if (!btn || btn.dataset.busy) return;
      // Disable after the browser has taken the submitter's value.
      setTimeout(function () { btn.dataset.busy = '1'; btn.disabled = true; btn.setAttribute('aria-busy', 'true'); }, 0);
      // Re-enable if the person comes back with the Back button.
      window.addEventListener('pageshow', function () { btn.disabled = false; delete btn.dataset.busy; btn.removeAttribute('aria-busy'); }, { once: true });
    });
  });
})();
