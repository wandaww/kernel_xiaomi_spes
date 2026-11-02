kind=$1; mod=$2; shift 2
for f do
    case "$f" in
        "$mod"/*) v="${f#"$mod"/}";;
        *) v="$f"; f="$mod/$f";;
    esac
    case "$v" in system/*)
        p="${v#system/}"; p="${p%%/*}"
        case "$p" in vendor|system_ext|product|odm|apex|oem|optics|prism|mi_ext|my_*)
            v="$p${v#system/$p}" ;;
        esac
    ;; esac
    if [ "$kind" = pair ]; then
        printf "/%s\0%s\0" "$v" "$f"
    elif [ "$kind" = opaque ]; then
        dir="${f%/.replace}"
        if [ -n "$(find "$dir" -mindepth 1 ! -name '.replace' ! -name '.remove' -print -quit 2>/dev/null)" ]; then
            printf "/%s\0%s\0" "${v%/.replace}" "$dir"
        fi
    elif [ "$kind" = del ]; then
        case "${f##*/}" in
            .replace) printf "/%s\0" "${v%/.replace}" ;;
            .remove)  printf "/%s\0" "${v%/.remove}"  ;;
            *)        printf "/%s\0" "$v"            ;;
        esac
    elif [ -d "$f" ]; then
        case "$(getfattr -n trusted.overlay.opaque "$f" 2>/dev/null)" in *"=\"y\""*) printf "/%s\0" "$v";; esac
    elif [ "${f##*/}" = ".replace" ]; then
        dir="${f%/.replace}"
        if [ -z "$(find "$dir" -mindepth 1 ! -name '.replace' ! -name '.remove' -print -quit 2>/dev/null)" ]; then
            printf "/%s\0" "${v%/.replace}"
        fi
    elif [ "${f##*/}" = ".remove" ]; then
        printf "/%s\0" "${v%/.remove}"
    else
        printf "/%s\0" "$v"
    fi
done
