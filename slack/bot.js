var SlackBot = require('slackbots');
const request = require('request');
var host;
 
// create a bot
var bot = new SlackBot({
    token: 'xoxb-102549979367-499379235237-39odlZymfiHt9h62dqqOtp1v', // Add a bot https://my.slack.com/services/new/bot and put the token 
    name: 'nsa'
});


var onStart = () => {
  var array = [];
  const token = 'xoxb-102549979367-499379235237-39odlZymfiHt9h62dqqOtp1v';
  // SHOULD RETURN SOMETHING LIKE
  // {"ok":true,"url":"https:\/\/maclawran.slack.com\/","team":"AltSlack","user":"nsa","team_id":"T30G5UTAT","user_id":"UEPB56X6Z"}
  request.post('https://slack.com/api/auth.test', {form: {token: token}}, function (error, response, body) { 
    if (!error && response.statusCode == 200) { 
      array=JSON.parse(response.body);
      host = require('url').parse(array.url).hostname.replace('.slack.com','');
      console.log("HOST: " + host);
    } else {
      console.log(error);
    }
  console.log('Bot started');
  });
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
    var botUsers = bot.getUsers();
    users = botUsers._value.members;
    var botChannels = bot.getChannels();
    channels = botChannels._value.channels;
    console.log("HOST: " + host);
  
    if(message.type === 'message' && Boolean(message.text)) {
      var channel = channels.find(channel => channel.id === message.channel);
      var usr = users.find(user => user.id === message.user);
      if (usr) {
          console.log("NAME: " + usr.name);
      }
      if (/^nsa:/.test(message.text)) {
        var command=(message.text).replace('nsa:', '');
        command.str.trim();
        console.log("===> NSA COMMAND: " + command);
        return;
      } else {
        console.log(message);
      }
  
      // BOTS HAVE A username BUT NO usr.name DEFINED
      if(usr && usr.name !== 'nsa') {
            var msg = "`" + usr.name + "` MEOW " + message.text;
            console.log("MSG: " + msg)
            bot.postMessageToChannel(channel.name, msg, params);
          /*
          if(message.text.toLowerCase().indexOf('bitch')) {
            keyword = 'bitch';
          }
          saveWord(channel,usr,keyword);
        }
            */
      }
    }
  }


bot.on('start', onStart);
bot.on('message', onMessage);
