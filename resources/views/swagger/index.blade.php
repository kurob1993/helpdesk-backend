
<!-- HTML for static distribution bundle build -->
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>{{ config('app.name') }} | Frontend API's Swagger</title>
    <link rel="stylesheet" type="text/css" href="{{asset('swagger/swagger-ui.css')}}" >
    <link rel="icon" type="image/png" href="{{asset('swagger/favicon-32x32.png')}}" sizes="32x32" />
    <link rel="icon" type="image/png" href="{{asset('swagger/favicon-16x16.png')}}" sizes="16x16" />
    <style>
      html
      {
        box-sizing: border-box;
        overflow: -moz-scrollbars-vertical;
        overflow-y: scroll;
      }

      *,
      *:before,
      *:after
      {
        box-sizing: inherit;
      }

      body
      {
        margin:0;
        background: #fafafa;
      }
    </style>
  </head>

  <body>
    <div id="swagger-ui"></div>

    <script src="{{asset('swagger/swagger-ui-bundle.js')}}"> </script>
    <script src="{{asset('swagger/swagger-ui-standalone-preset.js')}}"> </script>
    <script>
      window.onload = function() {
        function initSwaggerUi () {
          window.ui = SwaggerUIBundle({
            url: "{{ asset('swagger/swagger.yml') }}",
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
              SwaggerUIBundle.presets.apis,
              SwaggerUIStandalonePreset
            ],
            plugins: [
              SwaggerUIBundle.plugins.DownloadUrl
            ],
            layout: "StandaloneLayout",
            validatorUrl: null
          });
        }
        var xhr = new XMLHttpRequest();
        xhr.open('HEAD', document.location.href);
        xhr.onreadystatechange = function () {
          var url = '/api-docs';
          if (xhr.readyState === XMLHttpRequest.DONE) {
            url = xhr.getResponseHeader('Swagger-API-Docs-URL');
          } else {
            console.log('Unable to get the Swagger UI URL from the server (%s): %s', xhr.status, xhr.responseText);
          }
          initSwaggerUi(url);
        };
        xhr.send(null);
      }
    </script>
    
    
  </body>
</html>
