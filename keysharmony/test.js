const x = require('x-ray-scraper');
 
x('https://keysso.net/arrests', '.currArrests', [{
  info: 'li',
  pic: '.img-thumbnail@src'
}])
  .paginate('.nav-previous a@href')
  .limit(3)
  .write('results.json')