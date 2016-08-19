![apnscp Logo](https://apisnetworks.com/images/logo/logo.png)
## apnscp 
Artistic License Open Source release of all backend modules that power our control panel, apnscp. Modules may be interacted with by creating an API key in the control panel (Dev > API Keys). Use the endpoint cited in API Keys to correctly call the API. 

## Structure
Modules are laid out by module name. Each module name contains exposed public methods that may be invoved through the API. Any method prefixed with `_` or marked as `PRIVILEGE_SERVER_EXEC` may not be directly invoked, but may be indirectly through same-module chaining. Permissions are evaluated before calling the *module entry point*. A module that calls a method in itself (same-module chaining) does not abide by permissions. 

Methods may elevate the privileges through `query()` to speak with the backend service broker (apnscpd). apnscpd runs these methods with elevated privileges (root). Typically this is used sparingly when it is absolutely necessary.

### Sample code
For example, to get server uptime, call `get_uptime()` in the `common` module:
```php
  $endpoint = 'http://cp.apisnetworks.com:2082';
  $key = '1111-2222-3333-44444';
  $client = new SoapClient(
    $endpoint . '/apnscp.wsdl',
      array(
      'connection_timeout' => 5,
      'location'           => $endpoint.'soap?authkey='.$key,
      'uri'                => 'urn:net.apnscp.soap'
    )
  );
  print call_user_func(array($client, 'common_get_uptime'));
```
Returns `2 months 17 days 15 hours 32 mins` (or however long the server has been up).
