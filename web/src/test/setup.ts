import '@testing-library/jest-dom/vitest';
Object.defineProperty(window,'matchMedia',{writable:true,value:()=>({matches:false,addEventListener(){},removeEventListener(){}})});
class Observer {observe(){}unobserve(){}disconnect(){}}
Object.defineProperty(window,'IntersectionObserver',{value:Observer});
