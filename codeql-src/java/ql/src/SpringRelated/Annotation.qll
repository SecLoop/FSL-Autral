/*
	Author: Lousix
	Version: 2.0
    file: Annotation.qll
	Description: Spring的注解定义
*/

import java

/*
	定义路由注解识别类
	目前包括：
		@RequestMapping
		@PostMapping
		@GetMapping
*/
class MappingAnnotation extends Annotation{
    MappingAnnotation(){
        this.getType().getQualifiedName() = [
            "org.springframework.web.bind.annotation.RequestMapping",
            "org.springframework.web.bind.annotation.PostMapping",
            "org.springframework.web.bind.annotation.GetMapping",
            "org.springframework.web.bind.annotation.PutMapping",
            "org.springframework.web.bind.annotation.PatchMapping",
            "org.springframework.web.bind.annotation.DeleteMapping",
        ]
    }
}

class ClassMappingAnnotation extends Annotation{
    ClassMappingAnnotation(){
        this.getType().getQualifiedName() = [
            "org.springframework.web.bind.annotation.RestController",
            "org.springframework.stereotype.Controller",
        ]
    }
}

/*
	定义参数注解识别类
	目前包括：
		@RequestParam
		@RequestBody
*/
class ParamAnnotation extends Annotation{
    ParamAnnotation(){
        this.getType().getQualifiedName() = [
            "org.springframework.web.bind.annotation.RequestParam",
            "org.springframework.web.bind.annotation.RequestBody",
            "org.springframework.web.bind.annotation.PathVariable"
        ]
    }
}



predicate isMappingAnnotation(Annotation an) {
    an.getType().hasQualifiedName("org.springframework.web.bind.annotation","RequestMapping")
    or
    an.getType().hasQualifiedName("org.springframework.web.bind.annotation","PostMapping")
    or
    an.getType().hasQualifiedName("org.springframework.web.bind.annotation","GetMapping")
    or
    an.getType().hasQualifiedName("org.springframework.web.bind.annotation","PutMapping")
    or
    an.getType().hasQualifiedName("org.springframework.web.bind.annotation","PatchMapping")
    or
    an.getType().hasQualifiedName("org.springframework.web.bind.annotation","DeleteMapping")
}




predicate isClassMappingAnnotation(Annotation an) {
    an.getType().hasQualifiedName("org.springframework.web.bind.annotation","RestController")
    or
    an.getType().hasQualifiedName("org.springframework.stereotype","Controller")
}
