// Small, purposeful motion inside the app (GSAP). Only things that show
// progress or confirm an action: the progress ring fills and counts up, and
// on the client page the document just uploaded is highlighted.
(function () {
  if (!window.gsap || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  document.documentElement.classList.add('motion');
  var params = new URLSearchParams(location.search);
  var justUploaded = params.get('done');

  document.querySelectorAll('.ring').forEach(function (ring) {
    var arc = ring.querySelector('.arc');
    var num = ring.querySelector('.label b');
    if (!num) return;
    var m = num.textContent.match(/^(\d+)\/(\d+)$/);
    if (!m) return;
    var done = +m[1], total = +m[2];
    // After an upload, count on from where the client was; otherwise from zero.
    var from = justUploaded ? Math.max(0, done - 1) : 0;
    var c = arc ? parseFloat(arc.getAttribute('stroke-dasharray')) : 0;
    var count = { n: from };
    var tl = gsap.timeline({ defaults: { duration: justUploaded ? .7 : 1.1, ease: 'power3.out' }, delay: justUploaded ? .25 : .1 });
    if (arc) tl.fromTo(arc, { strokeDashoffset: c * (1 - from / total) }, { strokeDashoffset: c * (1 - done / total) }, 0);
    tl.to(count, { n: done, onUpdate: function () { num.textContent = Math.round(count.n) + '/' + total; } }, 0);
  });

  if (justUploaded && /^[0-9a-f-]{36}$/.test(justUploaded)) {
    var row = document.querySelector('[data-rid="' + justUploaded + '"]');
    if (row) {
      gsap.fromTo(row, { backgroundColor: 'rgba(169, 131, 76, .18)' }, { backgroundColor: 'rgba(169, 131, 76, 0)', duration: 1.6, ease: 'power2.out', delay: .2 });
      var mark = row.querySelector('.done-mark');
      if (mark) gsap.from(mark, { x: -8, autoAlpha: 0, duration: .5, ease: 'power2.out', delay: .2 });
    }
  }
})();
