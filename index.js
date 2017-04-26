var aws = require('aws-sdk');
var readline = require('readline');
var https = require('https');
var fs = require('fs');
var path = require('path');
var async = require('async');

var waf = new aws.WAF();

var botsConf = JSON.parse(fs.readFileSync(path.join('.', 'conf', 'bots.json')));

var wafConf = {
  "byteSetPrefix": "badbot-data",
  "byteSetIncrementBy" : 1,
  "filtersLimit": 10
};

var updateParams = function (botname) {
  return {
    'Action': 'INSERT',
    'ByteMatchTuple': {
      'FieldToMatch': {
        'Type': 'HEADER',
        'Data': 'User-Agent'
      },
      'PositionalConstraint': 'CONTAINS',
      'TargetString': botname,
      'TextTransformation': 'LOWERCASE'
    }
  };
};

//get badbots from mod_security
var getBadBotData = function(callback) {
  botsConf.url.forEach(function(url, index, array) {
    console.log(url);
    async.parallel([
      function(cback) {
        // get bot names
        var bots = [];
        https.get(url, function (response) {
          // create a reader object to read the list one line at a time
          var reader = readline.createInterface({ terminal: false, input: response });
          reader.on('line', function (line) {
            if (line && !line.trim().startsWith('#')) {
              var bot = line;
              // add bot to array if it not a duplicate
              if (bots.indexOf(bot) === -1) {
                bots.push(bot);
              }
            }
          });
          reader.on('close', function () {
            console.log(bots.length + ' bots read from the bad bots data at ' + url);
            cback(null, bots);
          });
        }).on('error', function (err) {
          console.error('Error downloading bad bots data at ' + url, err);
          cback(err);
        });
      },
      function(cback) {
        // get bytematchsets
        var params = {Limit: 1};
        var bytematchsets = [];
        (function createByteMatchSetArray() {
          waf.listByteMatchSets(params, function(err, bmsets) {
            if (err) {
              cback(err, null);
            } else {
              var nm = bmsets.NextMarker;
              bmsets.ByteMatchSets.forEach(function(bmset) {
                if(bmset.Name.toLowerCase().startsWith(wafConf.byteSetPrefix)) {
                  bytematchsets.push(bmset);
                }
              });
            }
            if (nm != null) {
              params = {Limit: 1, NextMarker: nm};
              createByteMatchSetArray();
            } else {
              // console.log("bytematchsets = " + bytematchsets.length);
              cback(null, bytematchsets);
            }
          });
        })();
      }
    ], function(err, result) {
      if (err) {
        callback(err, null);
      } else {
        var bots = result[0];
        var byteMatchSets = result[1];
        var updates = [];

        // compile a list ot bytematchsets; compare list of bots against them; add missing bots to bytematchsets
        async.map(byteMatchSets, function (bmset, cb) {
          waf.getByteMatchSet({ByteMatchSetId: bmset.ByteMatchSetId}, function(e, b) {
            if (e) {
              cb(e, null);
            } else {
              cb(null, b.ByteMatchTuples);
            }
          });
        }, function(e, tuples) {
          if (e) {
            console.log(e, e.stack);
          } else {
            // check if bots are already exist in bytesets.
            // if not, add them to existing bytesets that have room. Else, create new bytematchsets.
            for (var i =0; i < bots.length; i++) {
              var bot = bots[i];
              var found = false;
              tuples.forEach(function(tuple) {
                if (tuple.TargetString.toLowerCase() == bot.toLowerCase()) {
                  found = true;
                  bots.splice(i, 1);
                }
              });
              if (!found) {
                var tuple = updateParams(bot);
                updates.push(tuple);
              }
            }
            callback(null, updates);
          }
        });
      }
    });
  });
};

var updateByteMatchSets = function (event, context) {
  getBadBotData(function(err, byteMatchSets) {
    console.log(byteMatchSets);
  });
};

function callback(err, data) {
  if (err) {
    console.log(err, err.stack);
  } else {
    console.log(data);
  }
}

updateByteMatchSets(null, null);
