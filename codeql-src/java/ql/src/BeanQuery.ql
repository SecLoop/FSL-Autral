import java

predicate hasAncestor(Class cls) {
    count(cls.getAnAncestor()) != 2
    and
    cls.getAnAncestor().getName() != "Object"
    and
    cls.getAnAncestor().getName() != cls.getName()
}

Class getAncestor(Class cls){
    cls.getAnAncestor().getName() != "Object"
    and
    cls.getAnAncestor().getName() != cls.getName()
    and
    result = cls.getAnAncestor()
}

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

from Class cls, Field field
where 
    cls.getName() = "DemoUser"
    and
    field = getField(cls)
select cls,
    field,
    field.getType()