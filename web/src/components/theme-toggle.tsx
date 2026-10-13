import {Monitor,Moon,Sun} from 'lucide-react';
import {useTheme} from '../lib/context';
import {Button} from './ui';

const themes={
 light:{label:'浅色',next:'dark',icon:Sun},
 dark:{label:'深色',next:'system',icon:Moon},
 system:{label:'跟随系统',next:'light',icon:Monitor},
} as const;

export function ThemeToggle(){
 const{theme,setTheme}=useTheme();
 const current=themes[theme];
 const Icon=current.icon;
 const label=`当前主题：${current.label}，切换为${themes[current.next].label}`;
 return <Button variant="ghost" className="icon-button theme-toggle" aria-label={label} title={label} onClick={()=>setTheme(current.next)}><Icon size={18} strokeWidth={1.75} aria-hidden="true"/></Button>;
}
