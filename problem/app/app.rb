require 'openssl'
require 'base64'
require 'sinatra'
require 'json'

# $key = OpenSSL::Random.random_bytes(32)
$key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" #  練習用

def encrypt(message)
  enc = OpenSSL::Cipher.new("AES-256-CBC")
  enc.encrypt

  iv = OpenSSL::Random.random_bytes(enc.iv_len)
  enc.key = $key
  enc.iv = iv

  ciphertext = ""
  ciphertext << enc.update(message)
  ciphertext << enc.final

  iv + ciphertext
end

def decrypt(iv_ciphertext)
  dec = OpenSSL::Cipher.new("AES-256-CBC")
  dec.decrypt

  iv = iv_ciphertext[0, dec.iv_len]
  ciphertext = iv_ciphertext[dec.iv_len, iv_ciphertext.size - dec.iv_len]

  dec.key = $key
  dec.iv = iv

  message = ""
  message << dec.update(ciphertext)
  message << dec.final

  message 
end

configure do
  set :bind, '0.0.0.0'
end


get '/hint' do
  content_type :json
  token = {
    id: 9,
    admin: false,
  }
  token.to_json
end

get '/token' do
  content_type :json
  token = {
    id: 9,
    admin: false,
  }
  Base64.urlsafe_encode64(encrypt(token.to_json))
end

get '/check' do
  content_type :json
  response = {
    body: params['token'],
  }
  p params['token']

  begin
    message = decrypt(Base64.urlsafe_decode64(params['token']))
  rescue => e
    status 400
    return "decrypt error"
  end

  begin
    obj = JSON.parse(message)
  rescue => e
    status 400
    return "JSON error"
  end

  if obj['flag'] == true
    return "kurenaifCTF{flag}"
  end

  if obj['id'] == 0
    return "admin! (id=0)"
  elsif obj['admin']
    return "admin! (admin=true)"
  else
    return sprintf("userid: %d", obj['id'])
  end
end
