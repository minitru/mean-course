//Require MQTT library
var mqtt = require('mqtt');
// Define client connecting to our MQTT server
// clean: false means do not start new session on reconnect
// This allows us to use persistent sessions feature of MQTT protocol
// In addition clientId must be some unique for each client string
var client  = mqtt.connect('mqtt://localhost', {
clean: false,
clientId: 'console_client'
});
// Triggers on connect
// Cleant subscribes on topic with qos: 1 which means QOS level. Client will be getting all messages on reconnect.
// Then it publishes new message in to topic. This message will be stored in DB and sent to subscribers. Offline subscribers with QOS 1 will get it on reconnect.
//
client.on('connect', function () {
client.subscribe('/hello/s-pro', {qos: 1});
client.publish('/hello/s-pro', 'Hello, S-PRO!', {qos: 1});
});
// Do something when new message arrives.
client.on('message', function (topic, message) {
console.log(topic + ': ' + message.toString());
});