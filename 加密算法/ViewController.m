//
//  ViewController.m
//  加密算法
//
//  Created by weiguang on 2017/6/20.
//  Copyright © 2017年 weiguang. All rights reserved.
//

#import "ViewController.h"
#import "NSString+Hash.h"
#import "SSKeychain.h"
#import <LocalAuthentication/LocalAuthentication.h>
#import "EncryptionTools.h"

static NSString *salt = @"SSVDFBCXXC∆dfffd12323%^%&&*&*&*@#@#@#¥EEDCGCFCFCSER:L{P{KPOKOPKMLKMKL KLMKLMK NJBHG";

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextField *uid;
@property (weak, nonatomic) IBOutlet UITextField *pwd;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    
}
- (IBAction)login:(UIButton *)sender {
    
    NSString *uid = self.uid.text;
    NSString *pwd = self.pwd.text;
    
    // 发送加密之后的密码 MD5, 可以通过http://www.cmd5.com/ 反向查询
    //pwd = pwd.md5String;
    
    // 加盐 MD5
    // pwd = [pwd stringByAppendingString:salt].md5String;
    
    // HMAC -- 用一个密钥加密 并且做了两次散列
    // KEY :在真实的开发中，是从服务器中获取的，随机获取,保存
    pwd = [pwd hmacMD5StringWithKey:@"hank"];
    
    NSLog(@"现在的密码是：%@",pwd);
    
    // 模拟发送网络请求
    BOOL result = [self loginWithuid:uid pwd:pwd];
    // 服务器端直接保存 e10adc3949ba59abbe56e057f20f883e 加密后的字符
    if (result) {
        NSLog(@"登录成功!");
    }else {
        NSLog(@"登录失败!");
    }
    
}



- (BOOL)loginWithuid:(NSString *)uid pwd:(NSString *)pwd{
    if ([uid isEqualToString:@"hanck"] && [pwd isEqualToString:@"e9cdab82d48dcd37af7734b6617357e6"]) {
        return YES;
    }
    return NO;
}

// EncryptionTools的使用
- (void)testEncryptionTools{
    
    NSString *pwd = [[EncryptionTools sharedEncryptionTools] encryptString:@"hello" keyString:@"abc" iv:nil];
    NSLog(@"EncryptionTools加密：%@",pwd);
}



/************************************************/
/************************************************/
/************************************************/
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event{
    
    [self testEncryptionTools];
}

- (void)MD5test{
    //压缩性 : 任意长度的数据,算出的 MD5 值长度都是固定的，32个字符
    // 利用MD5 对字符串进行加密
    NSString *password = @"xiaoxue";
    password = [password md5String];
    NSLog(@"pwd1:%@",password);
    
    //加盐:可以保证 MD5加密之后更加安全
    NSString *salt = @"234567890-!@#$%^&*()_+QWERTYUIOP{ASDFGHJKL:XCVBNM<>";
    [password stringByAppendingString:salt];
    password = [password md5String];
    NSLog(@"pwd2:%@",password);

}

// 时间戳密码
/*
 动态密码：相同的密码明文+相同的加密算法-->因为每次登陆时间都不同,所以每次计算出的结果也都不相同.可以充分保证密码的安全性.
 
 服务器会计算两个时间值,当前时间和前一分钟的时间(比如:第59S发送的网络请求,一秒钟后服务器收到并作出响应,这时服务器当前时间比客户端发送时间晚一分钟，仍然能够判断准确的值)
 使用步骤
 */
- (void)timejiami{
 
    // 当前密码：
    NSString *username = @"zhangsan";
    NSString *password = @"123456";
    
    //  hmacKey值 获取MD5首次加密的值
    NSString *key = @"xiaomage";  // 这个key由服务器随机获取到
    NSString *hmacKey = [key md5String];
    
    // 加密过程
     // 1. 第一次加密：第一次 HMAC 运算
    password = [password hmacMD5StringWithKey:hmacKey];
    
    // 2.1 获得当前的时间
    NSDate *date = [NSDate date];
    
    // 2.2 获得当前时间的字符串
    // 实例化时间格式器
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    
    // 设置时间格式
    formatter.dateFormat = @"yyyy-MM-dd HH:mm";
    
     // 获取当前时间（要和服务器保持一致）
    NSString *dateStr = [formatter stringFromDate:date];
    
     // 3. 将第一次加密后的密码与当前时间的字符串拼接在一起
    password = [password stringByAppendingString:dateStr];
    
    // 4. 进行第二次 HMAC 加密
    password = [password hmacMD5StringWithKey:hmacKey];
    
    NSLog(@"%@",password);
    
// 访问接口，发送请求
    NSURL *url = [NSURL URLWithString:@"http://localhost/login/loginhmac.php"];
    
    // POST 要手动设置方法，因此为可变
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    
    // 设置请求方法
    request.HTTPMethod = @"POST";
    
    // 设置请求体内容
    NSString *body = [NSString stringWithFormat:@"username=%@&password=%@", username,password];
    request.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
    
    // 发送请求
    [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        
        NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSLog(@"%@", str);
    }] resume];
    
    
}


//钥匙串访问
/*
 参数介绍
 Password :需要存储的密码信息.
 Service :用来标识 app ,app的唯一标识符.
 account :账户信息,当前密码所对应的账号
 */

- (void)keyChain{
    // 获取应用程序唯一标识.
    NSString *bundleID = [NSBundle mainBundle].bundleIdentifier;
    
    
    // 利用第三方框架,将用户密码保存在钥匙串
    [SSKeychain setPassword:@"lwg80925" forService:bundleID account:@"wpf"];
    
    // 从钥匙串加载密码
    NSString *pwd = [SSKeychain passwordForService:bundleID account:@"wpf"];
    
    NSLog(@"%@",pwd);
}


//  指纹识别

- (void)zhiwen{
    // 获得当前系统版本号 ios8 以后可以用
    float version = [UIDevice currentDevice].systemVersion.floatValue;
    if (version < 8.0) {
        NSLog(@"系统版本太低，请升级");
        return;
    }
    
    // 实例化指纹识别对象,判断当前设备是否支持指纹识别功能(是否带有TouchID)
     // 1> 实例化指纹识别对象
    LAContext *laCtx = [[LAContext alloc] init];
    
    // 2> 判断当前设备是否支持指纹识别功能
    BOOL result = [laCtx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];
    if (!result) {
        NSLog(@"该设备不支持指纹识别功能");
        return;
    }
    
    // 指纹登陆(默认是异步方法)
    [laCtx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:@"指纹登录" reply:^(BOOL success, NSError * _Nullable error) {
         // 如果成功,表示指纹输入正确.
        if (success) {
            NSLog(@"指纹识别成功!");
        }else {
            NSLog(@"指纹识别错误,请再次尝试!");
        }
    }];
    
}



@end
