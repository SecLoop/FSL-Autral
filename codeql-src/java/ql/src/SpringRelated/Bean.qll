import java

/*
    判断是否存在父类
    判断方法：
        必须有两个以上的Ancestor，因为每个类似乎都有 自身 和 Object 作为 Ancestor
 */
predicate hasAncestor(Class cls) {
    count(cls.getAnAncestor()) != 2
    and
    cls.getAnAncestor().getName() != "Object"
    and
    cls.getAnAncestor().getName() != cls.getName()
}

/*

 */
Class getAncestor(Class cls){
    cls.getAnAncestor().getName() != "Object"
    and
    cls.getAnAncestor().getName() != cls.getName()
    and
    result = cls.getAnAncestor()
}

/*
    
 */
Field getField(Class cls){
    (
        hasAncestor(cls)
        and
        result = getField(getAncestor(cls))
    )
    or
    (
        result = cls.getAField()
    )
}