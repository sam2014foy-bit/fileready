// Marketing page motion: Lenis smooth scrolling, and a case card that fills up
// as the reader scrolls through one week of chasing. Without JS, or with
// reduced motion, every step is shown and the card stays in its first state.
(function () {
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var bar = document.querySelector('.h-bar');
  window.addEventListener('scroll', function () { bar.classList.toggle('scrolled', window.scrollY > 8); }, { passive: true });

  if (!window.gsap || !window.ScrollTrigger) { document.body.classList.add('no-motion'); return; }
  gsap.registerPlugin(ScrollTrigger);

  // Statuses per step for the 7 checklist items: r requested, u received (to check), a accepted, x sent back.
  var CHIP = { r: ['', 'Requested'], u: ['brass', 'To check'], a: ['good', 'Accepted'], x: ['bad', 'Sent back'] };
  var STATES = [
    { s: 'rrrrrrr', e: 'Email sent to Niamh with 7 documents' },
    { s: 'uuurrrr', e: 'Niamh uploaded 3 documents' },
    { s: 'aaxrrrr', e: 'Payslips sent back: page 2 is cut off' },
    { s: 'aaxrrrr', e: 'Reminder sent: 5 documents still needed' },
    { s: 'aauuurr', e: 'Niamh uploaded 3 documents' },
    { s: 'aaaaarr', e: 'Reminder sent by email and text' },
    { s: 'aaaaauu', e: 'All 7 documents in. Chasing stopped.' },
  ];
  var rows = Array.prototype.slice.call(document.querySelectorAll('.h-items li'));
  var arc = document.querySelector('.h-ring .arc');
  var doneEl = document.querySelector('.h-done');
  var eventBox = document.querySelector('.h-event');
  var eventText = document.querySelector('.h-event-text');
  var steps = Array.prototype.slice.call(document.querySelectorAll('.h-step'));
  var current = -1;
  var count = { n: 0 };

  function show(i) {
    if (i === current) return;
    var prev = current >= 0 ? STATES[current].s : null;
    current = i;
    var st = STATES[i];
    steps.forEach(function (el, k) { el.classList.toggle('on', k === i); });
    rows.forEach(function (li, k) {
      var code = st.s[k], chip = li.querySelector('.chip');
      chip.className = 'chip ' + CHIP[code][0];
      chip.textContent = CHIP[code][1];
      if (prev && prev[k] !== code && !reduce) {
        gsap.fromTo(li, { backgroundColor: 'rgba(169, 131, 76, .16)' }, { backgroundColor: 'rgba(169, 131, 76, 0)', duration: 1.2, ease: 'power2.out' });
        gsap.fromTo(chip, { scale: .85 }, { scale: 1, duration: .5, ease: 'back.out(3)' });
      }
    });
    // The ring counts what's in, as the app does: received or accepted.
    var done = st.s.replace(/[rx]/g, '').length;
    var d = reduce ? 0 : .8;
    gsap.to(arc, { strokeDashoffset: 1 - done / 7, duration: d, ease: 'power3.out' });
    gsap.to(count, { n: done, duration: d, ease: 'power3.out', onUpdate: function () { doneEl.textContent = Math.round(count.n); } });
    if (reduce) { eventText.textContent = st.e; return; }
    gsap.timeline()
      .to(eventText, { autoAlpha: 0, y: -6, duration: .15, ease: 'power1.in' })
      .add(function () { eventText.textContent = st.e; eventBox.classList.toggle('done', done === 7); })
      .fromTo(eventText, { autoAlpha: 0, y: 6 }, { autoAlpha: 1, y: 0, duration: .3, ease: 'power2.out' });
  }

  steps.forEach(function (el, i) {
    ScrollTrigger.create({
      trigger: el, start: 'top 60%', end: 'bottom 60%',
      onEnter: function () { show(i); }, onEnterBack: function () { show(i); },
    });
  });
  show(0);

  if (!reduce && window.Lenis) {
    var lenis = new Lenis({ lerp: 0.12, anchors: true });
    lenis.on('scroll', ScrollTrigger.update);
    gsap.ticker.add(function (t) { lenis.raf(t * 1000); });
    gsap.ticker.lagSmoothing(0);
  }

  // One entrance on load: the headline and lede settle in.
  if (!reduce) {
    gsap.from(['.h-hero h1', '.h-lede', '.h-actions', '.h-for'], { y: 24, autoAlpha: 0, duration: 1, stagger: .09, ease: 'power3.out', delay: .05 });
  }
})();
