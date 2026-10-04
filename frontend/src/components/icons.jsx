// Inline stroke icons, 1.75px on a 24px grid. They inherit currentColor.

function Icon({ size = 18, children, ...rest }) {
    return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
            strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...rest}>
            {children}
        </svg>
    )
}

export const ShieldMark = ({ size = 22 }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 2.5 4 5.6v6.1c0 4.9 3.3 8.4 8 9.8 4.7-1.4 8-4.9 8-9.8V5.6L12 2.5Z" fill="currentColor" />
        <path d="M8.4 12.2 11 14.7l4.8-5.2" fill="none" stroke="var(--surface)" strokeWidth="2"
            strokeLinecap="round" strokeLinejoin="round" />
    </svg>
)

export const PlusIcon = (p) => <Icon {...p}><path d="M12 5v14M5 12h14" /></Icon>
export const SendIcon = (p) => <Icon {...p}><path d="M12 19V5M6 11l6-6 6 6" /></Icon>
export const SunIcon = (p) => (
    <Icon {...p}>
        <circle cx="12" cy="12" r="4" />
        <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </Icon>
)
export const MoonIcon = (p) => <Icon {...p}><path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5Z" /></Icon>
export const MenuIcon = (p) => <Icon {...p}><path d="M4 7h16M4 12h16M4 17h16" /></Icon>
export const CloseIcon = (p) => <Icon {...p}><path d="M6 6l12 12M18 6 6 18" /></Icon>
export const ChevronIcon = (p) => <Icon {...p}><path d="m9 6 6 6-6 6" /></Icon>
export const CompareIcon = (p) => <Icon {...p}><rect x="3" y="4" width="7.5" height="16" rx="1.5" /><rect x="13.5" y="4" width="7.5" height="16" rx="1.5" /></Icon>
export const CheckIcon = (p) => <Icon {...p}><path d="m5 12.5 4.5 4.5L19 7.5" /></Icon>
export const StopIcon = (p) => <Icon {...p}><path d="M7 7l10 10M17 7 7 17" /></Icon>
export const RewriteIcon = (p) => <Icon {...p}><path d="M4 20h4L19 9l-4-4L4 16v4Z" /></Icon>
export const AlertIcon = (p) => <Icon {...p}><path d="M12 3 2.5 20h19L12 3Z" /><path d="M12 10v4M12 17.2v.1" /></Icon>
