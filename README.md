# tsp-http-client
A RFC3161 compliant http client to request timestamp to a trusted timestamp service provider

##Project structure
The project is wirtten in Java and it relies on bouncycastle libraries to encode and decode DER payload with ASN.1 structure. The main class is the TSAClient. The client work as single requestor and it stores digest, request and response for future use. There is also a TSAResponseViewer usefuel to decode and view response data info.

##tsp-http-client Properties
The TSAClient read in the classpath:it/luigibifulco/crypto/tsa/tsa.properties to search the tsa.properties file. These are the properties needed:

      #the url of timestamp service provider
      tsp.url=http://domain.to/tsaservice
      
      #the username provided by service provider for basic authentication
      tsp.username=basic auth user
      
      #the password provided by service provider for basic authentication
      tsp.password=basic auth pwd
      
      #a descriptive human readable identifier of the digest algorithm to use      
      tsp.digestAlgorithm=SHA256
      
      #set this to true to request a certificate in TimeStampResponse
      tsp.requestCert=true
      
      #set this to treu to automatically generate a nonce (reccomended)
      tsp.genNonce=true
      
      #work dir where to store digest, request and response for future use and validity check
      tsp.workdir=./.tmp
      
      #the data source to hash with digest algorithm and pass to message imprint
      tsp.dataPath=tsa-context/test.txt

##Usage
After properties are set you can use the TSAClient in this way:

      TSAClient client = new TSAClient();
	client.queryTimestamp();
      
if all gone well you should see digest file and request and response file in the tsp.workdir directory

##Known issues:

 - some tsp providers fill the response with non standard values such as -5 or -8 or -2, contact your provider for further info about it.
 - validity check is possibile reusing all files stored during request/response process.
 - the client was tested only with Aruba PEC provider, but it should works with standard RFC3161 server.
 
