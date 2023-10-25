import java
import semmle.code.java.dataflow.DataFlow

class TypeStringLib extends RefType {
  TypeStringLib() { this.hasQualifiedName("java.lang", "String") }
}

class StringValue extends MethodAccess {
    StringValue(){
      this.getCallee().getDeclaringType() instanceof TypeStringLib and
      this.getCallee().hasName("valueOf")
    }
}



//temp function
MethodAccess url(MethodAccess ma,DataFlow::Node node){
  exists( MethodAccess mc | mc = ma.getAChildExpr()| if mc.getCallee().hasName("url") and mc.getArgument(0) = node.asExpr() then result = mc else result = url(mc,node)
  )
}

MethodAccess m(DataFlow::Node node){
  exists(
      MethodAccess ma | ma.getCallee().hasName("build") and ma.getCallee().getDeclaringType().hasName("Builder") |result = url(ma,node)
  )
}