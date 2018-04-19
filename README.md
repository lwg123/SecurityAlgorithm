# SecurityAlgorithm
常用加密算法
包括：
AES/DES
/**
 *  加密字符串并返回base64编码字符串
 *
 *  @param string    要加密的字符串
 *  @param keyString 加密密钥
 *  @param iv        初始化向量(8个字节)
 *
 *  @return 返回加密后的base64编码字符串
 */
- (NSString *)encryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv;

/**
 *  解密字符串
 *
 *  @param string    加密并base64编码后的字符串
 *  @param keyString 解密密钥
 *  @param iv        初始化向量(8个字节)
 *
 *  @return 返回解密后的字符串
 */
- (NSString *)decryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv;

RSA加密算法：
 
时间戳密码
 动态密码：相同的密码明文+相同的加密算法-->因为每次登陆时间都不同,所以每次计算出的结果也都不相同.可以充分保证密码的安全性.
 
 服务器会计算两个时间值,当前时间和前一分钟的时间(比如:第59S发送的网络请求,一秒钟后服务器收到并作出响应,这时服务器当前时间比客户端发送时间晚一分钟，仍然能够判断准确的值)

//压缩性 : 任意长度的数据,算出的 MD5 值长度都是固定的，32个字符
// 利用MD5 对字符串进行加密
 
钥匙串访问
参数介绍
Password :需要存储的密码信息.
Service :用来标识 app ,app的唯一标识符.
account :账户信息,当前密码所对应的账号
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


 
