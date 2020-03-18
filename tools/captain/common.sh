echo_time()
{
    date "+[%F %R] $*"
}
export -f echo_time