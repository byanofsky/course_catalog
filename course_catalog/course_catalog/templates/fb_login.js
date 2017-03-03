function statusChangeCallback(response) {
  console.log('statusChangeCallback');
  console.log(response);
  if (response.status === 'connected') {
    // Logged into your app and Facebook.
    sendTokenToServer(response.authResponse.accessToken);
  } else if (response.status === 'not_authorized') {
    // The person is logged into Facebook, but not your app.
    document.getElementById('status').innerHTML = 'Please log ' +
      'into this app.';
  } else {
    // The person is not logged into Facebook, so we're not sure if
    // they are logged into this app or not.
    document.getElementById('status').innerHTML = 'Please log ' +
      'into Facebook.';
  }
}

function facebook_login() {
  FB.login(function(response) {
    statusChangeCallback(response)
  }, {scope: 'public_profile,email'});
}

window.fbAsyncInit = function() {
  FB.init({
    appId      : {{ config }},
    cookie     : true,  // enable cookies to allow the server to access
                        // the session
    xfbml      : true,  // parse social plugins on this page
    version    : 'v2.8' // use graph api version 2.8
  });

  FB.getLoginStatus(function(response) {
    statusChangeCallback(response);
  });
};

// Load the SDK asynchronously
(function(d, s, id) {
  var js, fjs = d.getElementsByTagName(s)[0];
  if (d.getElementById(id)) return;
  js = d.createElement(s); js.id = id;
  js.src = "//connect.facebook.net/en_US/sdk.js";
  fjs.parentNode.insertBefore(js, fjs);
}(document, 'script', 'facebook-jssdk'));

function sendTokenToServer(accessToken) {
  console.log(accessToken)
  console.log('Welcome!  Fetching your information.... ');
  FB.api('/me', function(response) {
    console.log('Successful login for: ' + response.name);
    document.getElementById('status').innerHTML =
      'Thanks for logging in, ' + response.name + '!';

    $.ajax({
      type: 'POST',
      url: '/fbconnect?state={{STATE}}',
      processData: false,
      data: accessToken,
      contentType: 'application/octet-stream; charset=utf-8',
      success: function(result) {
        // Handle or verify the server response if necessary.
        if (result) {
          $('#result').html('Login Successful!<br>' + result + '<br>Redirecting...');
          setTimeout(function() {
            window.location.href = "{{ url_for('view_all_courses') }}";
          }, 4000);
        } else {
          $('#result').html('Failed to make a server-side call. Check your configuration and console.');
        }
      }
    });
  });
}
