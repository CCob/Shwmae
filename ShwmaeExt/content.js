
function injectScript (src) {
    const s = document.createElement('script');
    s.src = chrome.runtime.getURL(src);
    s.onload = () => s.remove();
    (document.head || document.documentElement).append(s);
}


if (document.contentType === "text/html") {
  injectScript('webauthn-inject.js');    
}