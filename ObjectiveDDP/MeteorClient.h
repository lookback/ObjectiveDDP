#import "ObjectiveDDP.h"

@protocol DDPAuthDelegate;

@interface MeteorClient : NSObject<ObjectiveDDPDelegate>

@property (strong, nonatomic) ObjectiveDDP *ddp;
@property (weak, nonatomic) id<DDPAuthDelegate> authDelegate;
@property (strong, nonatomic) NSMutableDictionary *subscriptions;
@property (strong, nonatomic) NSMutableDictionary *subscriptionsParameters;
@property (strong, nonatomic) NSMutableSet *methodIds;
@property (strong, nonatomic) NSMutableDictionary *collections;
@property (copy, nonatomic) NSString *sessionToken;
@property (copy, nonatomic) NSString *userId;
@property (assign, nonatomic) BOOL websocketReady;
@property (assign, nonatomic) BOOL connected;
@property (nonatomic, assign) int retryAttempts;

#pragma mark Request/response
/** Send a request with the given methodName and parameters.
    @param notify Whether to send a "response_%d" NSNotification when response comes back
*/
- (NSString *)sendWithMethodName:(NSString *)methodName parameters:(NSArray *)parameters notifyOnResponse:(BOOL)notify;

/** Like sendWithMethodName:parameters:notifyOnResponse:YES but also calls your provided
    callback when the response comes back. */
- (NSString*)sendWithMethodName:(NSString *)methodName parameters:(NSArray *)parameters responseCallback:(void(^)(NSDictionary *response, NSError *error))responseCallback;

/** Fire-and-forget. Forwards to sendWithMethodName:parameters:notifyOnResponse:NO. */
- (void)sendWithMethodName:(NSString *)methodName parameters:(NSArray *)parameters;

#pragma mark Collections and subscriptions
- (void)addSubscription:(NSString *)subscriptionName;
- (void)addSubscription:(NSString *)subscriptionName withParameters:(NSArray *)parameters;
- (void)removeSubscription:(NSString *)subscriptionName;
- (void)resetCollections;

#pragma mark Login
- (void)logonWithUsername:(NSString *)username password:(NSString *)password;
- (void)signupWithUsername:(NSString *)username password:(NSString *)password fullname:(NSString*)fullname;
- (void)logout;

@end

@protocol DDPAuthDelegate <NSObject>

- (void)authenticationWasSuccessful;
- (void)authenticationFailed:(NSString *)reason;

@end


extern NSString *const MeteorClientDidConnectNotification;
extern NSString *const MeteorClientDidDisconnectNotification;

/** Errors due to transport (connection) problems will have this domain. For errors being reported
    from the backend, they will have the "errorType" key as their error domain. */
extern NSString *const MeteorClientTransportErrorDomain;
enum {
    /** Can't perform request because client isn't connected. */
    MeteorClientNotConnectedError,
    
    /** Request failed because websocket got disconnected before response arrived. */
    MeteorClientDisconnectedError,
};
