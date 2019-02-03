var fs = require("fs");
var path = require('path');
var SlackBot = require('slackbots');
const request = require('request');
var SimpleHashTable = require('simple-hashtable');
var hashtable = new SimpleHashTable();
const persist = require('persist');               /* ON DISK VERSION OF THE HASHTABLE */
var links = [];                                   /* ARRAY OF LINKS */
var host;
var user;
var mqtt = require('mqtt');
const client  = mqtt.connect('mqtt://dev.maclawran.ca', {
  clean: false,
  clientId: 'test'
});

// create a bot
var bot = new SlackBot({
    token: 'xoxb-102549979367-499379235237-39odlZymfiHt9h62dqqOtp1v', // Add a bot https://my.slack.com/services/new/bot and put the token 
    name: 'nsa'
});

var onStart = () => {
  // INITIALIZE ON-DISK DATA IF WE HAVE ANY
  // READ OUR LINKS IN
  links = JSON.parse(fs.readFileSync('./links.json', 'utf8'));
  for (let link of links) {
    client.subscribe(link.remote, {qos: 1});
    console.log("*** INBOUND QUEUE " + link.remote);
  }
  console.log(links);

  const token = 'xoxb-102549979367-499379235237-39odlZymfiHt9h62dqqOtp1v';
  // SHOULD RETURN SOMETHING LIKE
  // {"ok":true,"url":"https:\/\/maclawran.slack.com\/","team":"AltSlack","user":"nsa","team_id":"T30G5UTAT","user_id":"UEPB56X6Z"}

  request.post('https://slack.com/api/auth.test', {form: {token: token}}, function (error, response, body) { 
    if (!error && response.statusCode == 200) { 
      array=JSON.parse(response.body);
      user = array.user;
      host = require('url').parse(array.url).hostname.replace('.slack.com','');
      // console.log("HOST: " + host + "\nUSER: " + user);
    } else {
      console.log(error);
    }
    //Require MQTT library
     // Define client connecting to our MQTT server
    // clean: false means do not start new session on reconnect
    // This allows us to use persistent sessions feature of MQTT protocol
    // In addition clientId must be some unique for each client string

    // SUBSCRIBE TO ALL THE THINGS WE NEED TO LISTEN TO
    // HOW DO WE KNOW WHAT WE'RE SUBSCRIBED TO?
    // OR DO WE JUST ASSUME ANYTHING THE BOT HEARS SHOULD
    // HAVE SOME ENDPOINT ASSOCIATED WITH IT?
    // AND THAT SHOULD BE DONE ON THE FIRST MESSAGE 
    // WE GET FROM THAT SLACK GROUP?
    // DO WE NEED THIS? client.subscribe('/hello/s-pro', {qos: 1});
    // IT SEEMS TO PERSIST ONCE WE'VE SUBSCRIBED ONCE...
  });
  console.log('Bot started');
};

/* NOT USING BUT IS A GOOD WORKING EXAMPLE
bot.on('start', function() {
    // more information about additional params https://api.slack.com/methods/chat.postMessage
    var params = {
        icon_emoji: ':cat:'
    };
    
    // define channel, where bot exist. You can adjust it there https://my.slack.com/services 
    bot.postMessageToChannel('general', 'meow!', params);
    
    // define existing username instead of 'user_name'
    bot.postMessageToUser('user_name', 'meow!', params); 
    
    // If you add a 'slackbot' property, 
    // you will post to another user's slackbot channel instead of a direct message
    bot.postMessageToUser('user_name', 'meow!', { 'slackbot': true, icon_emoji: ':cat:' }); 
    
    // define private group instead of 'private_group', where bot exist
    bot.postMessageToGroup('private_group', 'meow!', params); 
});
*/

var onMessage = (message) => {
    var params = {
        icon_emoji: ':nsa:'
    };
    users = [];
    channels = [];
    cmdargs = [];
    var link = {
      channel: "",
      remote: ""
    }
    var remotechannel;
    var botUsers = bot.getUsers();
    users = botUsers._value.members;
    var botChannels = bot.getChannels();
    channels = botChannels._value.channels;
    console.log("INBOUND FROM SLACK: " + host);

    if(message.type === 'message' && Boolean(message.text)) {
      var channel = channels.find(channel => channel.id === message.channel);
      var usr = users.find(user => user.id === message.user);
      if (usr) {
          console.log("NAME: " + usr.name);
      }
      
      // BOT COMMANDS BEGIN WITH nsa:
      // link URL
      // console.log(message);
      if (/^nsa:/.test(message.text)) {
        cmdargs = (message.text).match(/\S+/gi);    // SPLIT INTO WORDS
        link.channel = message.channel;             // CURRENT SLACK CHANNEL
        command = cmdargs[1];
        console.log("COMMAND: " + command);
        if (cmdargs.length > 2) {
          remotechannel = cmdargs[2];
          var parts = cmdargs[2].split("/");
          link.remote = ('/' + parts[2] + '/' + parts[3] + '/' + parts[4]).replace(">","");
        }

        switch(command) {
          case 'link':
            // LINK TO REMOTE CHANNEL - JUST SAVE CHANNEL NAME
            // ADD A MAP LINK FROM C2ZREB04A TO THE REMOTE URL
            // THE REMOTE URL WILL LOOK SOMETHING LIKE THIS
            // https://maclawran.slack.com/messages/C2ZREB04A/whats_new/
            // link.remote = cmdargs[2];
            // MAKE SURE OUR LINK BEGINS WITH A /
            // SLACK ENCLOSES THE URL WITH <> - KILL THE LAST ONE
            // OUR LINK SHOULD BE maclawran.slack.com/messages/C2ZREB04A
            console.log("• COMMAND: LINK " + link.channel + "TO " + link.remote);
            client.subscribe(link.remote, {qos: 1});
            links.push(link);
            savelinks(links);
            // console.log("====== LINKS");
            // console.log(links);
            bot.postMessage(message.channel, "`Channel linked... in order to work the other channel has to link back to here as well`", params);
            break;
          case 'unlink':
            console.log("• COMMAND: UNLINK " + link.channel + "TO " + link.remote);
            client.unsubscribe(link.remote);
            links.pop(link);
            savelinks(links);
            bot.postMessage(message.channel, "`Unlinked group`", params);
            break;
          case 'list':
            console.log("• COMMAND: LIST ");
            console.log(links);
          case 'status':
            const result = links.filter( chan => chan.channel === message.channel);
            if (result.length > 0) {
              var res = '`' + JSON.stringify(result) + '`';
              bot.postMessage(message.channel, res, params);
            } else {
              bot.postMessage(message.channel, "`Not mirroring this channel`", params);
            }
            break;
 
        default:
        }

        // console.log("====== ARRAY");
        // FIND ONE
        // const result = links.find( chan => chan.channel === message.channel);
        // FIND ALL
        // const result = links.filter( chan => chan.channel === message.channel);
        // THE ANSWER IS IN result.channel AND result.remote
        // console.log(result);


        // console.log("====== HASHTABLE");
        hashtable.put(link.channel, link.remote);
        // console.log(hashtable.get(link.channel));
        // console.log(hashtable.keys());
        return;
      } else {
        console.log(message);
      }
  
      // OUTBOUND - FROM BOT TO REMOTE CHANNEL
      // JUST POST TO WHATEVER LINKED TO
      // BOTS HAVE A username BUT NO usr.name DEFINED
      if(usr && usr.name !== 'nsa') {
            var msg = "`" + usr.name + "` MEOW " + message.text;
            console.log("MSG: " + msg)
            const result = links.filter( chan => chan.channel === message.channel);
            // THIS WILL PUBLISH TO ALL MATCHING CHANNELS
            for (let item of result) {
              console.log("*** OUTBOUND QUEUE " + item.remote);
              client.publish(item.remote, msg, {qos: 1});
              console.log(item); // Will display contents of the object inside the array
            }
            // client.publish('/hello/s-pro', 'Hello, S-PRO!', {qos: 1});
            // bot.postMessageToChannel(channel.name, msg, params);
      }
    }
  }

bot.on('start', onStart);
bot.on('message', onMessage);

// INBOUND FROM MESSAGE QUEUE
client.on('message', function (topic, message) {
  var params = {
    icon_emoji: ':nsa:'
  };
  // NOW WE NEED TO KNOW WHAT CHANNEL TO POST TO
  // SO LOOK IT UP
  var chan = path.basename(topic);
  console.log("*** INBOUND QUEUE " + chan);
  console.log(topic);
  console.log(message.toString());
  // POST MESSAGE BY NAME
  // bot.postMessageToChannel('general',message.toString(), params);
  // POST MESSAGE BY ID
  bot.postMessage(chan, message.toString(), params);

  // bot.postMessageToChannel(channel.name, msg, params);
  // bot.postMessageToChannel('random', message.toString(), params);
  // topic appears unused...
  console.log(message.chan + ': ' + message.toString());
});

// SAVE LINKS ON DISK WHEN WE LINK TO SOMETHING
var savelinks = (linkfile) => {
  fs.writeFile("./links.json", JSON.stringify(linkfile, null, 4), (err) => {
    if (err) {
        console.error(err);
        return;
    };
  });
}

// READ LINKS FROM DISK
// HANDLE THE FIRST PASS WHERE THERE'S NO FILE YET
// THIS STILL CRASHES
var readlinks = (linkfile) => {
  if(!fs.existsSync(file)) {
    console.log("File not found");
  } else {
    fs.readFile("./links.json", JSON.stringify(linkfile, null, 4));
  };
};

