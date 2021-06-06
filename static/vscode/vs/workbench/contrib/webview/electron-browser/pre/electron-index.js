(function(){"use strict";const{ipcRenderer:s,contextBridge:n}=require("electron"),t={onElectron:!0,useParentPostMessage:!0,postMessage:(o,e)=>{s.sendToHost(o,e)},onMessage:(o,e)=>{s.on(o,e)},focusIframeOnCreate:!0,isInDevelopmentMode:!1};t.onMessage("devtools-opened",()=>{t.isInDevelopmentMode=!0}),document.addEventListener("DOMContentLoaded",o=>{window.onmessage=e=>{s.sendToHost(e.data.command,e.data.data)}}),n.exposeInMainWorld("vscodeHost",t)})();

//# sourceMappingURL=electron-index.js.map
