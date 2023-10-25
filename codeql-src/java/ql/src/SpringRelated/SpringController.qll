/*
	Author: Lousix
	Version: 2.0
*/

import java
import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.dataflow.ExternalFlow
import Annotation
import semmle.code.java.frameworks.spring.SpringController

/*
    提取 Class 注解中的路由
 */
string findStringInClass(Class c){
    (
        isMappingAnnotation(c.getADeclaredAnnotation())
        and
        result = findString(c.getADeclaredAnnotation().(MappingAnnotation).getValue("value"))
    )
    or
    (
        not isMappingAnnotation(c.getADeclaredAnnotation())
        and 
        isClassMappingAnnotation(c.getADeclaredAnnotation())
        and 
        result = findString(c.getADeclaredAnnotation().(ClassMappingAnnotation).getValue("value"))
    )
    
}

/*
    提取 Method 注解中的路由
 */
string findStringInMethod(Method method){
    result = findString(method.getADeclaredAnnotation().(MappingAnnotation).getValue("value"))
    or
    result = findString(method.getADeclaredAnnotation().(ClassMappingAnnotation).getValue("value"))  
}

/*
    提取注解中的路由
 */
string findString(Expr expr) { 
    (
        expr.getType().toString() = "String"
        and 
        expr.toString().regexpReplaceAll("\"","") != ""
        and
        result = format(expr.toString().regexpReplaceAll("\"",""))
    )
    or
    (        
        expr.getType().toString() = "String"
        and 
        expr.toString().regexpReplaceAll("\"","") = ""
        and 
        result = ""
    )
    or
    result = findString(expr.getAChildExpr())
}

/*
    拼接注解中的路由
 */
bindingset[path]
string format(string path){
    (path.matches("/%") and path.matches("%/") and result = path.prefix(path.length()-1))
    or 
    (path.trim().matches("/%") and not path.matches("%/") and result = path)
    or
    (not path.matches("/%") and path.matches("%/") and result = "/" + path.prefix(path.length()-1))
    or
    (not path.matches("/%") and not path.matches("%/") and result = "/" + path)
}   


/*
	获取 路由路径
*/
string getControllerRoute(Class c, Method m){
    exists(  Method method, string routePath1, string routePath2|
        method = c.getAMethod()
        and 
        method = m
        // and
        // method instanceof SpringRequestMappingMethod
        and
        // routePath1 = findString(c.getADeclaredAnnotation().(MappingAnnotation).getValue("value"))
        routePath1 = findStringInClass(c)
        and 
        routePath2 = findStringInMethod(method)
        and
        result = routePath1.replaceAll("\"", "") + routePath2.replaceAll("\"", "")
        // result = routePath2.replaceAll("\"", "")
    )
}

/*
	判断是否为用户可输入的接口
	判断依据：
		该方法是否带有 MappingAnnotation 路由注解特征
*/
predicate isTargetMethod(Method m){
    m.getAnAnnotation() instanceof MappingAnnotation
}

/*
    提取 ContentType值
*/
string getContentType(Method method){
    (
        method.getAnAnnotation().toString() = "GetMapping"
        and result = ""
    ) or (
            method.getAnAnnotation().getValue("consumes").toString() != "" //.(CompileTimeConstantExpr).getStringValue().toLowerCase().trim() != ""
            and method.getAnAnnotation().getValue("consumes").toString() != "{...}" //.(CompileTimeConstantExpr).getStringValue().toLowerCase().trim() != ""
            and result = method.getAnAnnotation().getValue("consumes").toString() //(CompileTimeConstantExpr).getStringValue().toLowerCase().trim()
    ) or (
        method.getAParameter().getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody")
        and
        (
            method.getAnAnnotation().getValue("consumes").toString() = ""
            or method.getAnAnnotation().getValue("consumes").toString() = "{...}"
        )
        and result = "application/json"
    ) or (
        result =  method.getAnAnnotation().getValue("consumes").getAChildExpr().(CompileTimeConstantExpr).getStringValue().toLowerCase().trim()
        or result = method.getAnAnnotation().getValue("consumes").(CompileTimeConstantExpr).getStringValue().toLowerCase().trim()
    ) or (
        if method.getAnAnnotation().toString() = "GetMapping" or method.getAParameter().getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody")
        then result = ""
        else not exists(string contentType | 
            (
                contentType = method.getAnAnnotation().getValue("consumes").getAChildExpr().(CompileTimeConstantExpr).getStringValue().toLowerCase().trim()
                or contentType = method.getAnAnnotation().getValue("consumes").(CompileTimeConstantExpr).getStringValue().toLowerCase().trim()
            ) and contentType != ""
        ) and result = "application/x-www-form-urlencoded"
    )
}

/*
    提取请求方法
 */
string  getRequestMethod(Method method){
    if exists( string requestMethod | 
        method.getAnAnnotation().(MappingAnnotation).getType().hasQualifiedName("org.springframework.web.bind.annotation","RequestMapping")
        and
        requestMethod = method.getAnAnnotation().getValue("method").getAChildExpr().(CompileTimeConstantExpr).getStringValue().toLowerCase().trim()
        and requestMethod != ""
        )
    then result = method.getAnAnnotation().getValue("method").getAChildExpr().(CompileTimeConstantExpr).getStringValue().toLowerCase().trim()
    else result = method.getAnAnnotation().(MappingAnnotation).getType().getName()
}