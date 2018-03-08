import calendar
from datetime import datetime, date
# 2011-05-21 17:26:31 "4dd7f5c7"
utc_time = "2011-05-21 17:26:31"
d = datetime.strptime(utc_time,"%Y-%m-%d %H:%M:%S")
ts = calendar.timegm(d.timetuple())
print( hex(ts) )
# without calendar.timegm
DAY = 24*60*60
x = (date(2011,5,21).toordinal() - date(1970, 1, 1).toordinal()) * DAY
x= x+17*60*60+26*60+31
print( hex(x) )
