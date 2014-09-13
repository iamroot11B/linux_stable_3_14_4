#ifndef TYPECHECK_H_INCLUDED
#define TYPECHECK_H_INCLUDED

/*
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
 */
/*!
 * dummy와 dummy2의 타입이 다른 경우에는 컴파일 warning이 발생되도록 하는 역활
 * typeof(x) -> x와 같은 타입으로 대체됨
 * (void)의 의미는 잘 모르겠음 -> gcc에서 void를 없이 컴파일해도 결과는 똑같음
 * 뒤에 1이 붙은 것은 리턴 값을 항상 1로 하겠다는 의미
 */
#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})

/*
 * Check at compile time that 'function' is a certain type, or is a pointer
 * to that type (needs to use typedef for the function type.)
 */
#define typecheck_fn(type,function) \
({	typeof(type) __tmp = function; \
	(void)__tmp; \
})

#endif		/* TYPECHECK_H_INCLUDED */
