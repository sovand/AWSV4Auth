using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AWSV4Auth
{
    public class AWSV4Auth
    {
        #region "Properties"
        private string AwsAccessKey { get; set; }
        private string AwsSecretKey { get; set; }
        private string Path { get; set; }
        private string Region { get; set; }
        private string Service { get; set; }
        private string HttpMethodName { get; set; }
        private Dictionary<string, string> Headers { get; set; }
        private string Payload { get; set; }
        private string HmacAlgorithm { get; set; }
        private string Aws4Request { get; set; }
        private string SignedHeaders { get; set; }
        private string XAmzDate { get; set; }
        private string CurrentDate { get; set; }
        #endregion

        #region "Constants"
        private const string K_HEX_ALPHABET = "0123456789ABCDEF";
        private const string K_HMAC_ALGORITHM = "AWS4-HMAC-SHA256";
        private const string K_AWS4_REQUEST_NAME = "aws4_request";
        private const string K_AMAZON_DATE_HEADER_NAME = "x-amz-date";
        private const string K_AUTHORIZATION_HEADER_NAME = "Authorization";
        private const string K_DATETIME_FORMAT = "yyyyMMdd'T'HHmmss'Z'";
        private const string K_DATE_FORMAT = "yyyyMMdd";
        #endregion

        /// <summary>
        /// Constructor to instantiate the class with all required parameters for PAAPI V5 requests
        /// </summary>
        /// <param name="awsAccessKey">Access Key</param>
        /// <param name="awsSecretKey">Secret Key</param>
        /// <param name="path">Path to the operation</param>
        /// <param name="region">Amazon Marketplace region</param>
        /// <param name="service">PAAPI Service name</param>
        /// <param name="httpMethodName">HTTP Method name</param>
        /// <param name="headers">Header parameters</param>
        /// <param name="payload">Request payload</param>
        public AWSV4Auth(string awsAccessKey, string awsSecretKey, string path, string region, string service,
            string httpMethodName, Dictionary<string, string> headers, string payload)
        {
            AwsAccessKey = awsAccessKey;
            AwsSecretKey = awsSecretKey;
            Path = path;
            Region = region;
            Service = service;
            HttpMethodName = httpMethodName;
            Headers = headers;
            Payload = payload;
            HmacAlgorithm = K_HMAC_ALGORITHM;
            Aws4Request = K_AWS4_REQUEST_NAME;

            XAmzDate = GetTimeStamp();
            CurrentDate = GetDate();
        }


        /// <summary>
        /// Returns all the Header data to be used to call the Amazon PAAPI V5 API
        /// </summary>
        /// <returns></returns>
        public Dictionary<string, string> GetHeaders()
        {
            Headers.Add(K_AMAZON_DATE_HEADER_NAME, XAmzDate);

            // Step 1: CREATE A CANONICAL REQUEST
            var canonicalURL = PrepareCanonicalRequest();

            // Step 2: CREATE THE STRING TO SIGN
            String stringToSign = PrepareStringToSign(canonicalURL);

            // Step 3: CALCULATE THE SIGNATURE
            String signature = calculateSignature(stringToSign);

            // Step 4: CALCULATE AUTHORIZATION HEADER
            if (signature != null)
            {
                Headers.Add(K_AUTHORIZATION_HEADER_NAME, BuildAuthorizationString(signature));
                return Headers;
            }
            else
            {
                return null;
            }
        }

        #region "Private methods"
        /// <summary>
        /// Prepares the canonical request
        /// </summary>
        /// <returns></returns>
        private string PrepareCanonicalRequest()
        {
            StringBuilder canonicalUrl = new StringBuilder();

            canonicalUrl.Append(HttpMethodName.ToUpper()).Append("\n");

            canonicalUrl.Append(Path).Append("\n").Append("\n");

            StringBuilder signedHeaderBuilder = new StringBuilder();
            var sortedHeaders = Headers.OrderBy(h => h.Key);
            if (sortedHeaders != null)
            {
                foreach (var entrySet in sortedHeaders)
                {
                    String key = entrySet.Key;
                    String value = entrySet.Value;
                    signedHeaderBuilder.Append(key.ToLower().Trim()).Append(";");
                    canonicalUrl.Append(key.ToLower().Trim()).Append(":").Append(value.Trim()).Append("\n");
                }
                canonicalUrl.Append("\n");
            }
            else
            {
                canonicalUrl.Append("\n");
            }

            SignedHeaders = signedHeaderBuilder.ToString().Substring(0, signedHeaderBuilder.Length - 1);
            canonicalUrl.Append(SignedHeaders).Append("\n");

            Payload = Payload == null ? "" : Payload;
            canonicalUrl.Append(ToHex(Payload));

            return canonicalUrl.ToString();
        }

        /// <summary>
        /// Prepares the string to sign
        /// </summary>
        /// <param name="canonicalUrl"></param>
        /// <returns></returns>
        private string PrepareStringToSign(string canonicalUrl)
        {
            String stringToSign = "";
            stringToSign = HmacAlgorithm + "\n";
            stringToSign += XAmzDate + "\n";
            stringToSign += CurrentDate + "/" + Region + "/" + Service + "/" + Aws4Request + "\n";
            stringToSign += ToHex(canonicalUrl);
            return stringToSign;
        }

        /// <summary>
        /// Calculates Signature Hash
        /// </summary>
        /// <param name="stringToSign"></param>
        /// <returns></returns>
        private string calculateSignature(string stringToSign)
        {
            byte[] signatureKey = GetSignatureKey(AwsSecretKey, CurrentDate, Region, Service);
            byte[] signature = HmacSha256(signatureKey, stringToSign);
            return BytesToHex(signature);
        }

        /// <summary>
        /// Builds the authorization header string
        /// </summary>
        /// <param name="signature"></param>
        /// <returns></returns>
        private string BuildAuthorizationString(string signature)
        {
            return HmacAlgorithm + " "
                    + "Credential=" + AwsAccessKey + "/" + GetDate() + "/" + Region + "/" + Service + "/" + Aws4Request + ", "
                    + "SignedHeaders=" + SignedHeaders + ", "
                    + "Signature=" + signature;
        }

        /// <summary>
        /// Converts a string to HEX value
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private string ToHex(string data)
        {
            var sha1 = SHA256.Create();
            byte[] inputBytes = Encoding.UTF8.GetBytes(data);
            byte[] outputBytes = sha1.ComputeHash(inputBytes);
            return BytesToHex(outputBytes);
        }

        /// <summary>
        /// Returns computed hash for the data and key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] HmacSha256(byte[] key, string data)
        {
            String algorithm = "HmacSHA256";
            KeyedHashAlgorithm kha = KeyedHashAlgorithm.Create(algorithm);
            kha.Key = key;

            return kha.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        /// <summary>
        /// Generates Signature key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="date"></param>
        /// <param name="regionName"></param>
        /// <param name="serviceName"></param>
        /// <returns></returns>
        private byte[] GetSignatureKey(string key, string date, string regionName, string serviceName)
        {
            byte[] kSecret = Encoding.UTF8.GetBytes("AWS4" + key);
            byte[] kDate = HmacSha256(kSecret, date);
            byte[] kRegion = HmacSha256(kDate, regionName);
            byte[] kService = HmacSha256(kRegion, serviceName);
            byte[] kSigning = HmacSha256(kService, Aws4Request);
            return kSigning;
        }

        /// <summary>
        /// Returns HEX value for a byte array
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string BytesToHex(byte[] bytes)
        {
            StringBuilder result = new StringBuilder(bytes.Length * 2);

            foreach (byte b in bytes)
            {
                result.Append(K_HEX_ALPHABET[(int)(b >> 4)]);
                result.Append(K_HEX_ALPHABET[(int)(b & 0xF)]);
            }

            return result.ToString().ToLower();
        }

        /// <summary>
        /// Returns UTC date in yyyyMMdd'T'HHmmss'Z' format
        /// </summary>
        /// <returns></returns>
        private string GetTimeStamp()
        {
            DateTime dateTime = DateTime.UtcNow;
            return dateTime.ToString(K_DATETIME_FORMAT);
        }

        /// <summary>
        /// Returns UTC date in yyyyMMdd format
        /// </summary>
        /// <returns></returns>
        private string GetDate()
        {
            DateTime dateTime = DateTime.UtcNow;
            return dateTime.ToString(K_DATE_FORMAT);
        }
        #endregion
    }
}
