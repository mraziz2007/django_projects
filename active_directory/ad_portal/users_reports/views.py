from django.shortcuts import render, HttpResponseRedirect, redirect
from django.contrib.auth.decorators import login_required
# - Authentication models and functions

from django.contrib.auth.models import auth, User
from django.contrib.auth import authenticate, login, logout

import os
from datetime import datetime, timedelta
import time
import re

import ldap3
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPCursorError

from dotenv import load_dotenv
load_dotenv()

from .forms import CreateUserForm, LoginForm, ADUserChangePasswordForm, SetStatusForm, LockSetStatusForm
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash



domain = os.getenv("DOMAIN")
server = os.getenv("SERVER")
user_name = os.getenv("USER_NAME")
password = os.getenv("PASSWORD")
group_dn = os.getenv("GROUP")

    
def convert_file_time(timestamp):
    pattern = r'[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])\s[0-9]{2}:[0-9]{2}:[0-9]{2}'
    result = re.search(pattern, timestamp)
    return result.group()


def return_account_expire_datetime(max_pwd_age, pwd_last_set):

    pwd_last_set = convert_file_time(str(pwd_last_set))
    max_pwd_age_in_days = int(str(max_pwd_age).split('days')[0])
    
    # Current date and time
    currentDT = datetime.now()

    account_expires_date = datetime.strptime(pwd_last_set, '%Y-%m-%d %H:%M:%S') + timedelta(days=max_pwd_age_in_days)
    return account_expires_date


def modify_user(conn, dn, user_attribute, user_attr_value):
    conn.modify(str(dn), {str(user_attribute): [(MODIFY_REPLACE, [str(user_attr_value)])]})


def change_password(conn, dn, new_password, old_password):
    
    ldap3.extend.microsoft.modifyPassword.ad_modify_password(conn, dn, new_password, old_password=old_password)


def sorted_list(users_details):
    
    count = 1
    # Sort the users dict
    new_users_details_list = sorted(users_details, key=lambda d: d['user_full_name'])

    # Add id to the users
    for x in new_users_details_list:
        x.update({'id': count})
        count += 1

    return new_users_details_list


def useruid(server, domain, user_name, password, ldap_field, login):
    """Connect to a LDAP and check the uid matching the given field data"""
    uid = False
    c = Connection(server, user='{}\\{}'.format(domain, user_name), password=password, authentication=NTLM, auto_bind=True)

    if c.result["description"] != "success":
        print("Error connecting to the LDAP with the service account")
        return False

    # Look for the user entry.
    if not c.search('DC=3INSYS,DC=COM',
                    "(" + ldap_field + "=" + login + ")") :
        print("Error: Connection to the LDAP with service account failed")
    else:
        if len(c.entries) >= 1 :
            if len(c.entries) > 1 :
                print("Error: multiple entries with this login. "+ \
                          "Trying first entry...")
            uid = c.entries[0].entry_dn
        else:
            print("Error: Login not found")
        c.unbind()
    
    return uid


def try_ldap_login(server, domain, user_name, password, ldap_field, login, login_password):
    """ Connect to a LDAP directory to verify user login/passwords"""
    result = "Wrong login/password"
    
    # 1. connection with service account to find the user uid
    
    uid = useruid(server, domain, user_name, password, ldap_field, login)
    
   
    if uid: 
        # 2. Try to bind the user to the LDAP
        c = Connection(server, user = uid , password = login_password, auto_bind = True)
        c.open()
        c.bind()
        result =  c.result["description"] # "success" if bind is ok
        c.unbind()

    return result


def fetch_ldap(server, domain, user_name, password):

    max_pwd_age = None
    users_details = []
    check_if_email_sent = None
    count = 1

    server = Server(server, get_info=ALL)
    
    conn = Connection(server, user='{}\\{}'.format(domain, user_name), password=password, authentication=NTLM, auto_bind=True)

    '''
    ## Searching the root directory to find the Max Password Age set for Domain Accounts. ##
    '''

    conn.search('DC=3INSYS,DC=COM', '(objectclass=domain)', attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
    
    for e in conn.entries:
        if 'maxPwdAge' in e:
            e.maxPwdAge
            max_pwd_age = e.maxPwdAge

    '''
    ## Searching the accounts in User OU in the domain to find their attributes. ##
    '''

    conn.search('OU=Users,OU=3INSYS,DC=3INSYS,DC=COM', '(objectclass=person)', attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
    # print(conn.entries)
    for e in conn.entries:
        # print(e)
        try:
            user_details = {}

            user_details['user_sam_account_name'] = str(e.sAMAccountName)
            
            user_details['user_full_name'] = str(e.cn)

            user_details['user_dn'] = str(e.distinguishedName)

            pwd_last_set = str(e.pwdLastSet)
            user_details['user_pwd_last_set'] = convert_file_time(str(pwd_last_set))
            
            user_details['user_account_control'] = int(str(e.userAccountControl))
            
            user_details['user_principle_name'] = str(e.userPrincipalName)
            
        
        except LDAPCursorError as e:
            print(e)

        if 'lockoutTime' in e:
                if str(e.lockoutTime) == '0':
                    user_details['user_lockout_status'] = 'unlocked'
                elif str(e.lockoutTime) == '1601-01-01 00:00:00+00:00':
                    user_details['user_lockout_status'] = 'unlocked'
                else:
                    user_details['user_lockout_status'] = str(e.lockoutTime)
        else:
            user_details['user_lockout_status'] = 'unlocked'
        
        pw_expires_datetime = return_account_expire_datetime(max_pwd_age, pwd_last_set)
        
        today = datetime.strptime(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), '%Y-%m-%d %H:%M:%S')
        remaining_date_password_expires = pw_expires_datetime - today

        user_details['user_account_remaining_days_for_password_expire'] = int(remaining_date_password_expires.days)

        users_details.append(user_details)

    # # modify_user(conn, users_details['test user']['user_dn'], 'userAccountControl', 514)
    # # print(conn.result)
    # # print(users_details)
    conn.unbind()

    # # Sort the users dict
    # myKeys = list(users_details.keys())
    # myKeys.sort()
    # sorted_dict = {i: users_details[i] for i in myKeys}

    # # Add id to the users
    # for x in sorted_dict:
    #     sorted_dict[x].update({'id': count})
    #     count += 1

    # return sorted_dict
    
    return users_details


def get_ldap_group_members(server, domain, user_name, password, group_dn):

    group_members = []

    # server = Server(server, get_info=ALL)
    
    conn = Connection(server, user='{}\\{}'.format(domain, user_name), password=password, authentication=NTLM, auto_bind=True)

    conn.search(
    search_base=group_dn,
    search_filter='(objectClass=group)',
    search_scope='SUBTREE',
    attributes = ['member']
    )

    for entry in conn.entries:

        for member in entry.member.values:
            conn.search('DC=3INSYS,DC=COM', f'(distinguishedName={member})', attributes=['sAMAccountName'])

            members_sAMAccountName = conn.entries[0].sAMAccountName.values

            for member_user in members_sAMAccountName:
                group_members.append(member_user)

    conn.unbind()

    return group_members


# Create your views here.

def register(request):

    form = CreateUserForm()

    if request.method == "POST":

        username = request.POST.get('username')
        email = request.POST.get('email')
        errors = []

        try:
            myuser = User.objects.get(username=username)
            errors.append('Username already exists.')
            context = {'registerform':form,
                    'errors': errors}
            return render(request, 'users_reports/register.html', context=context)
        except:

            username_error = False
            username_typo = False
            email_error = False
            
        
            if len(username.split('.')) <= 1:
                username_error == True
                errors.append("Username should be entered as 'john.doe'.")

            if '@' in username:

                username_typo == True
                errors.append("There is a typo '@' in the username.")

            if not '@3insys' in email:
                
                email_error = True
                errors.append("This is not a company email. e.g. 'john.doe@3insys.com'.")
                

            if errors:
                context = {'registerform':form,
                    'errors': errors}
                return render(request, 'users_reports/register.html', context=context)

            if not (username_error or username_typo or email_error):
                
                form = CreateUserForm(request.POST)

                if form.is_valid():
                    
                    form.save()
                    
                    return redirect("users_login")
                
    context = {'registerform':form}

    return render(request, 'users_reports/register.html', context=context)


def users_login(request):

    form = LoginForm()

    if request.method == 'POST':

        form = LoginForm(request, data=request.POST)

        username = request.POST.get('username')
        password = request.POST.get('password')
        
        try:
            myuser = User.objects.get(username=username)

            user = authenticate(request, username=username, password=password)
            
            if user is None:
                context = {'loginform':form,
                               'error': 'Invalid credential.'}
                return render(request, 'users_reports/login.html', context=context)

            if form.is_valid():
            
                if user is not None:

                    auth.login(request, user)

                    return redirect("index")

        except:
            context = {'loginform':form,
                       'error': 'Username does not exists.'}
            return render(request, 'users_reports/login.html', context=context)


    context = {'loginform':form}

    return render(request, 'users_reports/login.html', context=context)
    
    # if request.method == 'POST':
    #     form = UsersLoginsForms(request.POST)
    #     if form.is_valid():
    #         login_username = form.cleaned_data['username']
    #         login_username_password = form.cleaned_data['password']
    #         ldap_field = 'sAMAccountName'
    #         try:
    #             response = try_ldap_login(server, domain, user_name, password, ldap_field, login_username, login_username_password)
    #         except Exception as e:
    #             print(e)


    #         if response == 'success':
    #             return redirect('index')
    #         else:
    #             form = UsersLoginsForms()
                
    #             return render(request, 'users_reports/login.html', {
    #                 'form': form,
    #                 'failed': True
    #             })
    # else:
    #     form = UsersLoginsForms()
    #     return render(request, 'users_reports/login.html', {
    #         'form': form
    #     })
            
    # form = UsersLoginsForms()
    # return render(request, 'users_reports/login.html', {
    #     'form': form
    # })


def user_logout(request):

    auth.logout(request)

    return redirect("users_login")


def get_full_users_list():
    users_details = fetch_ldap(server, domain, user_name, password)
    list_of_users = sorted_list(users_details)
    return list_of_users


def get_filtered_user_list(app_logged_in_user):
    filtered_user_list = []
    users_details = fetch_ldap(server, domain, user_name, password)

    for each_user in users_details:
        if str(app_logged_in_user) in each_user['user_sam_account_name']:
            filtered_user_list.append(each_user)
            break
    
    sorted_filtered_user_list = sorted_list(filtered_user_list)

    return sorted_filtered_user_list


@login_required()
def index(request):

    adchangepasswordform = ADUserChangePasswordForm()
    accountsetstatusform = SetStatusForm()
    accountsetlockstatusform = LockSetStatusForm()
    app_logged_in_user = request.user
    
    filtered_user_list = []
        
    users_details = fetch_ldap(server, domain, user_name, password)

    for each_user in users_details:
        if str(app_logged_in_user) in each_user['user_sam_account_name']:
            filtered_user_list.append(each_user)
            break

    list_of_users = sorted_list(users_details)
    # print(list_of_users)
    
    sorted_filtered_user_list = sorted_list(filtered_user_list)
    
    admin_group_members = get_ldap_group_members(server, domain, user_name, password, group_dn)

    context1 = {
                'admin_group_members': admin_group_members,
                'adpasswordchangeform': adchangepasswordform,
                'accountsetstatusform': accountsetstatusform,
                'accountsetlockstatusform': accountsetlockstatusform,
            }
    
    context2 = {
                'adpasswordchangeform': adchangepasswordform,
                'accountsetstatusform': accountsetstatusform,
                'accountsetlockstatusform': accountsetlockstatusform,
                'not_authorized': True,
            }

    if request.method == 'GET':

        if str(app_logged_in_user) in admin_group_members and app_logged_in_user.is_superuser:
            full_users_list = get_full_users_list()
            additional_context = {'users': full_users_list}
            context1.update(additional_context)
            return render(request, 'users_reports/index.html', context=context1)
        else:
            filtered_user_list = get_filtered_user_list(app_logged_in_user)
            additional_context = {'users': filtered_user_list}
            context2.update(additional_context)
            return render(request, 'users_reports/index.html', context=context2)
    
    
    if request.method == 'POST':
        server_obj = Server(server, use_ssl=True, get_info=ALL)
        conn = Connection(server_obj, user='{}\\{}'.format(domain, user_name), password=password, authentication=NTLM, auto_bind=True)
        user_dn = request.POST.get('user_dn')
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        set_activate_status = request.POST.get('set_activate_status')
        set_deactivate_status = request.POST.get('set_deactivate_status')
        set_unlock_status = request.POST.get('set_unlock_status')
        alert_message = None

        if old_password or new_password or confirm_password:
            try:
                change_password(conn, user_dn, new_password, None)
                if conn.result['description'] == 'success':
                    alert_message = 'Password changed successfully.'
                else:
                    alert_message = 'Password changed successfully.'
            except Exception as e:
                print(e)
                alert_message = e

            if str(app_logged_in_user) in admin_group_members and app_logged_in_user.is_superuser:
                full_users_list = get_full_users_list()
                additional_context = {'users': full_users_list,
                                      'alert': alert_message}
                context1.update(additional_context)
                return render(request, 'users_reports/index.html', context=context1)
            else:
                filtered_user_list = get_filtered_user_list(app_logged_in_user)
                additional_context = {'users': filtered_user_list,
                                      'alert': alert_message}
                context2.update(additional_context)
                return render(request, 'users_reports/index.html', context=context2)

        if set_activate_status:
            print('set_activate_status:', set_activate_status)
            modify_user(conn, user_dn, "userAccountControl", 512)
            if conn.result['description'] == 'success':
                alert_message = 'Account successfully enabled.'
            else:
                alert_message = 'Error occured while enabling the user account.'
            if str(app_logged_in_user) in admin_group_members and app_logged_in_user.is_superuser:
                full_users_list = get_full_users_list()
                additional_context = {'users': full_users_list,
                                      'alert': alert_message}
                context1.update(additional_context)
                return render(request, 'users_reports/index.html', context=context1)
            else:
                filtered_user_list = get_filtered_user_list(app_logged_in_user)
                additional_context = {'users': filtered_user_list,
                                      'alert': alert_message}
                context2.update(additional_context)
                return render(request, 'users_reports/index.html', context=context2)
                
        if set_deactivate_status:
            print('set_deactivate_status:', set_deactivate_status)
            modify_user(conn, user_dn, "userAccountControl", 514)
            if conn.result['description'] == 'success':
                alert_message = 'Account successfully disabled.'
            else:
                alert_message = 'Error occured while disabling the user account.'
            if str(app_logged_in_user) in admin_group_members and app_logged_in_user.is_superuser:
                full_users_list = get_full_users_list()
                additional_context = {'users': full_users_list,
                                      'alert': alert_message}
                context1.update(additional_context)
                return render(request, 'users_reports/index.html', context=context1)
            else:
                filtered_user_list = get_filtered_user_list(app_logged_in_user)
                additional_context = {'users': filtered_user_list,
                                      'alert': alert_message}
                context2.update(additional_context)
                return render(request, 'users_reports/index.html', context=context2)

        if set_unlock_status:
            print('set_unlock_status:', set_unlock_status)
            modify_user(conn, user_dn, "lockoutTime", 0)
            if conn.result['description'] == 'success':
                alert_message = 'User account successfully been unlocked.'
            else:
                alert_message = 'Error occured while unlocking the user account.'
            if str(app_logged_in_user) in admin_group_members and app_logged_in_user.is_superuser:
                full_users_list = get_full_users_list()
                additional_context = {'users': full_users_list,
                                      'alert': alert_message}
                context1.update(additional_context)
                return render(request, 'users_reports/index.html', context=context1)
            else:
                filtered_user_list = get_filtered_user_list(app_logged_in_user)
                additional_context = {'users': filtered_user_list,
                                      'alert': alert_message}
                context2.update(additional_context)
                return render(request, 'users_reports/index.html', context=context2)
            

def portal_change_password(request):

    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            
            return redirect('users_login')
        else:
            form = PasswordChangeForm(request.user)
            context = {
            'form': form,
            'failed': True
            }
            return render(request, 'users_reports/portal_change_password.html', context=context)
    
    form = PasswordChangeForm(request.user)
    context = {
    'form': form
    }
    return render(request, 'users_reports/portal_change_password.html', context=context)