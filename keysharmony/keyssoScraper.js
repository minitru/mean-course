var fs = require('fs');
var path = require('path');

var cheerio = require('cheerio');
var sscanf = require('sscanf');
const url = 'https://keysso.net/arrests';

const request = require('request');
var download = function(uri, filename, callback){
  request.head(uri, function(err, res, body){    
    request(uri).pipe(fs.createWriteStream(filename)).on('close', callback);
  });
};

request(url, function (error, response, html) {
    if (!error && response.statusCode == 200) {
        var $ = cheerio.load(html);
        var name = new Array();
        var counts = new Array();
        var felony = new Array();
        var counts = new Array();
        // $('li').each(function (i, e) {
          // hobbies[i] = $(this).text();
        $('#arrest-list').each(function(i, element){

          // BIG MUGSHOT - MAY NOT HAVE RIGHT 
          var mugshotUrl = $(element).parent().parent().find('a').attr('href');
          // SMALL MUGSHOT
          // var mugshotUrl = $(element).parent().parent().find('img').attr('src');
          var fullname = $(element).parent().parent().find('img').attr('alt');
          mugshot = fullname.replace(/\s/g , "-");
          console.log("MUGSHOT: " + mugshot);
          console.log("NAME: " + fullname);
          // HOW DO WE NAME THE MUGSHOT?
          // JUST USE THE LAST NAME FOR NOW
          download(mugshotUrl, './mugshots/' + mugshot, function(){
            console.log('Downloaded mugshot');
          });

          var arrest = $(element).text();
          console.log("********** NEW ARREST *************");
          var officer = sscanf(arrest, "Arresting Officer/Agency: %S");
          name = sscanf(arrest, "%s, %S was arrested on %S at %S", );
          var address = sscanf(arrest, "Address: %S");
          var occupation = sscanf(arrest, "Occupation: %S");
          var location = sscanf(arrest, "Arrest Location: %S");
          var incident = sscanf(arrest, "Incident #: %S");
          felony = sscanf(arrest, " %d Felony Count %S");
          // DON'T KNOW WHY THIS DOESN'T WORK AT ALL
          // counts = sscanf(arrest, "%s Count %S");
          //var arraignment = sscanf(arraignment, "Arraignment: %S");

           // var dob = sscanf($(this).text(), "Date of Birth: %d/%d/%d");
          // console.log(location);
          // console.log(dob);
          // Our parsed meta data object
          var metadata = {
            name: name,
            address: address,
            occupation: occupation,
            location: location,
            officer: officer,
            incident: incident,
            felony: felony
            //arraignment: arraignment
          };
          console.log(metadata);
        });
      }
})