Step 1: Generate the HMAC-SHA256 Signature

#import <CommonCrypto/CommonCrypto.h>

// Method to generate HMAC-SHA256 signature
NSString *generateHMACSHA256Signature(NSString *message, NSString *secret) {
    const char *cKey  = [secret cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [message cStringUsingEncoding:NSUTF8StringEncoding];

    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);

    NSData *HMACData = [NSData dataWithBytes:cHMAC length:sizeof(cHMAC)];
    NSString *base64String = [HMACData base64EncodedStringWithOptions:0];

    return base64String;
}


Step 2: Create the String to Sign

#import <Foundation/Foundation.h>

// Method to create the string to sign
NSString *createStringToSign(NSString *method, NSString *endpoint, NSString *timestamp, NSString *body) {
    NSString *stringToSign = [NSString stringWithFormat:@"%@\n%@\n%@\n%@", method, endpoint, timestamp, body];
    return stringToSign;
}

Step 3: Send the API Request
#import <Foundation/Foundation.h>

void sendVisaAPIRequest(NSString *apiKey, NSString *sharedSecret, NSString *method, NSString *endpoint, NSString *body) {
    NSString *urlString = [NSString stringWithFormat:@"https://api.visa.com%@", endpoint];
    NSURL *url = [NSURL URLWithString:urlString];

    // Generate timestamp
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"UTC"]];
    NSString *timestamp = [dateFormatter stringFromDate:[NSDate date]];

    // Create the string to sign
    NSString *stringToSign = createStringToSign(method, endpoint, timestamp, body);

    // Generate the HMAC-SHA256 signature
    NSString *signature = generateHMACSHA256Signature(stringToSign, sharedSecret);

    // Create the request
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setHTTPMethod:method];
    [request setValue:apiKey forHTTPHeaderField:@"x-api-key"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    [request setValue:signature forHTTPHeaderField:@"x-signature"];
    [request setValue:timestamp forHTTPHeaderField:@"x-timestamp"];
    [request setHTTPBody:[body dataUsingEncoding:NSUTF8StringEncoding]];

    // Send the request
    NSURLSession *session = [NSURLSession sharedSession];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            NSLog(@"Error: %@", error);
        } else {
            NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
            NSLog(@"Status Code: %ld", (long)[httpResponse statusCode]);
            NSString *responseString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            NSLog(@"Response: %@", responseString);
        }
    }];
    [task resume];
}

// Example usage
NSString *apiKey = @"YOUR_API_KEY";
NSString *sharedSecret = @"YOUR_SHARED_SECRET";
NSString *method = @"POST";
NSString *endpoint = @"/v1/your_api_endpoint";
NSString *body = @"{\"field1\":\"value1\",\"field2\":\"value2\"}";

sendVisaAPIRequest(apiKey, sharedSecret, method, endpoint, body);



