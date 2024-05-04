// chat/static/room.js

console.log("Sanity check from room.js.");
let chatLog = document.querySelector("#chatLog");
let chatMessageInput = document.querySelector("#chatMessageInput");
let chatMessageSend = document.querySelector("#chatMessageSend");
let socket = new WebSocket("ws://" + document.location.host + "/ws/session/" + document.querySelector("#id").textContent);
socket.onmessage = (event) => {
    text = JSON.parse(event.data)['data']
    chatLog.value += text
    if (text.include("Successful:")) {
        alert(text);
    }
};
// socket.onclose = function(event) {
//   if (event.wasClean) {
//     console.log(`[close] Connection closed cleanly, code=${event.code} reason=${event.reason}`);
//   } else {
//     // e.g. server process killed or network down
//     // event.code is usually 1006 in this case
//     chatLog.value+='[close] Connection died!'+"\n"
//   }
// };
console.log(socket)
// focus 'chatMessageInput' when user opens the page
chatMessageInput.focus();

// submit if the user presses the enter key
chatMessageInput.onkeyup = function (e) {
    if (e.keyCode === 13) {  // enter key
        chatMessageSend.click();
    }
};
// clear the 'chatMessageInput' and forward the message

chatMessageSend.onclick = function () {
    if (chatMessageInput.value.length === 0) return;
    if (chatMessageInput.value === "clear") chatLog.value = "";
    // TODO: forward the message to the WebSocket
    else {
        chatLog.value += ">> " + chatMessageInput.value + "\n";
        socket.send(chatMessageInput.value);
    }
    chatMessageInput.value = "";
};