// Inject external script instead of inline script
const script = document.createElement("script");
script.src = chrome.runtime.getURL("injected.js");
script.onload = function () {
  this.remove();
};
(document.head || document.documentElement).appendChild(script);

// Listen for messages from injected script
window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  if (event.data.type === "COOKIE_ACCESS_DETECTED") {
    chrome.runtime.sendMessage(event.data);
  }
});
