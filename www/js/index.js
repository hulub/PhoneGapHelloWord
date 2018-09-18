/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

var video = document.createElement('video');
var canvasElement = document.getElementById('canvas');
var canvas = canvasElement.getContext('2d');

var app = {
  // Application Constructor
  initialize: function () {
    app.bindEvents();
  },
  // Bind Event Listeners
  //
  // Bind any events that are required on startup. Common events are:
  // 'load', 'deviceready', 'offline', and 'online'.
  bindEvents: function () {
    $(document).bind('deviceready', app.onDeviceReady);
    $(document).on('click', '#scan', app.startCameraRecording)
    $(document).on('click', '#rescan', app.startCameraRecording)
    $(document).on('click', '#scan-close', app.stopCameraRecording)
    $(document).on('submit', 'form#decrytpion-form', app.decrypt)
  },
  // deviceready Event Handler
  //
  // The scope of 'this' is the event. In order to call the 'receivedEvent'
  // function, we must explicitly call 'app.receivedEvent(...);'
  onDeviceReady: function () {
    app.initializeView();
  },
  // Update DOM on a Received Event
  initializeView: function () {
    $('#input-data').show()
  },

  startCameraRecording: function () {
    navigator.mediaDevices.getUserMedia({
      video: true
    }).then(function (stream) {
      video.srcObject = stream;
      video.setAttribute('playsinline', true); // required to tell iOS safari we don't want fullscreen
      video.play();
      requestAnimationFrame(app.tick);
    });
  },

  stopCameraRecording: function() {
    if (video.srcObject)
      video.srcObject.getTracks().forEach(function (track) {
        track.stop()
      });
    video.pause();
  },

  tick: function () {
    if (video.readyState === video.HAVE_ENOUGH_DATA) {

      canvasElement.height = video.videoHeight;
      canvasElement.width = video.videoWidth;
      canvas.drawImage(video, 0, 0, canvasElement.width, canvasElement.height);

      var imageData = canvas.getImageData(0, 0, canvasElement.width, canvasElement.height);
      var code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "dontInvert",
      });
      if (code) {
        // extract data
        var text_hex = code.data.split(',');
        var cryptogram_randomness_hex = text_hex[0]
        var cryptogram_ciphertext_hex = text_hex[1]
        var public_key_hex = text_hex[2]
        var randomness_hex = text_hex[3]

        $('#cryptogram').val(cryptogram_randomness_hex + '\n' + cryptogram_ciphertext_hex)
        $('#public-key').val(public_key_hex)
        $('#randomness').val(randomness_hex)

        // close camera recording
        app.stopCameraRecording()
        $('body').pagecontainer('change', '#data-page');
        return;
      }
    }
    requestAnimationFrame(app.tick);
  },

  decrypt: function () {
    var cryptogram_hex = $(this).find('#cryptogram').val().replace('\n', ',')
    var public_key_hex = $(this).find('#public-key').val()
    var randomness_hex = $(this).find('#randomness').val()

    var cryptogram = ElGamalPointCryptogram.fromString(cryptogram_hex)
    var public_key = pointFromBits(sjcl.codec.hex.toBits(public_key_hex))
    var randomness = sjcl.bn.fromBits(sjcl.codec.hex.toBits(randomness_hex));

    // invert cryptogram so you can decrypt with the randomness
    cryptogram = new ElGamalPointCryptogram(public_key, cryptogram.ciphertext_point)
    var vote = cryptogram.decrypt(randomness)
    var vote_hex = sjcl.codec.hex.fromBits(pointToBits(vote, true))

    $('#vote-point').val(vote_hex)

    try {
      var vote_decoding = pointToVote(vote)
      switch (vote_decoding.vote_encoding_type) {
        case vote_encoding_types.TEXT:
          $('#vote-text-span').text(vote_decoding.vote)
          $('#vote-text').show()
          $('#decrypted-success').show()
          break;
        case vote_encoding_types.IDS:
          var $vote_ids_list = $('#vote-ids-list').empty()
          vote_decoding.vote.filter(function (id) {
              return id != 0
            }
          ).forEach(function (id) {
            $vote_ids_list.append('<li>' + '<span>' + id + '</span>' + '</li>')
          })
          $('#vote-ids').show()
          $('#decrypted-success').show()
          break;
        case vote_encoding_types.BLANK:
          $('#vote-text-span').text('BLANK')
          $('#vote-text').show()
          $('#decrypted-success').show()
          break;
      }
    }
    catch(err) {
      $('#decrypted-error').show()
    }

    $('#decrypted-vote-header').show()
    $('#decrypted-vote-content').show()

    return false
  }
};