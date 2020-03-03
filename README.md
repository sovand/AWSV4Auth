# AWSV4Auth
AWS V4 Authorization header generator

For those who uses Amazon Product Advertisement API(PAAPI), there was no .Net code available for signature/Authorization Header generation process. The recent version of Amazon PAAPI V5 uses AWS V4 Auth Signature. The documentation is available here if you use Java or PHP. The documentationn can be found here: https://webservices.amazon.com/paapi5/documentation/without-sdk.html

# How to use this
1. Download the AWSV4Auth.cs and add this file as an Existing item in the project
2. 

            var headers = new Dictionary<string, string>()
            {
                {"content-encoding", "amz-1.0" },
                {"content-type", "application/json; charset=utf-8" },
                {"host", "webservices.amazon.com" },
                {"x-amz-target", "com.amazon.paapi5.v1.ProductAdvertisingAPIv1.SearchItems" }
            };
            var payload = "{\"Marketplace\":\"www.amazon" + "<use locale>" + "\",\"PartnerType\":\"Associates\",\"PartnerTag\":\"" + "<associated tag>" + "\",\"Keywords\":\""
                + "<Keywords i.e. kindle>" + "\",\"SearchIndex\":\"All\",\"ItemCount\":3,\"Resources\":[" + "<For available resources, visit https://webservices.amazon.com/paapi5/documentation/browsenodeinfo.html>" + "]}";
                var auth = new AWSV4Auth("<AWS Access key>", "<AWS Secret Key>", "/paapi5/searchitems", "us-east-1", "ProductAdvertisingAPI", "POST", headers, payload);
            var resHeaders = auth.GetHeaders();

            var requestUri = "https://webservices.amazon.com/paapi5/searchitems";
            var response = await PostRequest(requestUri, resHeaders, payload);
3.

                var request = (HttpWebRequest)WebRequest.Create(requestUri);

                request.Method = "POST";
                request.Headers.Add("Content-Encoding", "amz-1.0");
                request.Headers.Add("Authorization", headers["Authorization"]);
                request.Headers.Add("x-amz-target", headers["x-amz-target"]);
                request.Headers.Add("x-amz-date", headers["x-amz-date"]);
                request.ContentType = "application/json; charset=utf-8";
                var responseContent = new MemoryStream();

                using (var streamWriter = new StreamWriter(request.GetRequestStream()))
                {
                    streamWriter.Write(payload);
                }

                using (WebResponse response = await request.GetResponseAsync())
                {
                    using (Stream stream = response.GetResponseStream())
                    {
                        await stream.CopyToAsync(responseContent);
                    }
                }

                return Encoding.ASCII.GetString(responseContent.ToArray());
