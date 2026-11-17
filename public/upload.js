// Client upload page: upload as soon as a file is chosen, so each document
// needs one tap. Without this script the page still works with its buttons.
document.documentElement.classList.add('js');
document.querySelectorAll('form.item-side input[type=file]').forEach(function (input) {
  input.addEventListener('change', function () {
    if (!input.files || !input.files.length) return;
    var form = input.form;
    form.classList.add('busy');
    var status = form.querySelector('.uploading');
    if (status) status.textContent = 'Uploading ' + input.files[0].name + '…';
    form.submit();
  });
});
