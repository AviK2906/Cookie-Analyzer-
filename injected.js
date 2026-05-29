(function () {
  const original = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");

  if (!original) return;

  Object.defineProperty(document, "cookie", {
    get: function () {
      window.postMessage({
        type: "COOKIE_ACCESS_DETECTED",
        url: window.location.href,
        time: new Date().toISOString()
      }, "*");

      return original.get.call(document);
    },
    set: original.set
  });
})();
