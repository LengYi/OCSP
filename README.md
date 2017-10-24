# OCSP
签名有效性校验--->被封、过期、移除(个签、企签)

支持ipa、app、mobileprovision格式的直接检测，AppStore
上的app不支持检测,因为包里面不含mobileprovision证书。

注意:
   该工程开发环境为 xcode8.3.2, xcode 9 运行  SecOCSPRequest.h 文件编译报错,暂时没有修复,项目中有编译好的包先用，或者自己修复bug