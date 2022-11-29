# frozen_string_literal: true

# name: sensitive_check
# about: check sensitive texts and iamges
# version: 0.1
# authors: WANG WEI FENG
# url: https://github.com/hiddenvillage/sensitive_check.git


enabled_site_setting :sensitive_enabled

require 'faraday/logging/formatter'
require 'json'

load File.expand_path("../../../lib/new_post_manager.rb", __FILE__)
load File.expand_path("../../../app/services/word_watcher.rb", __FILE__)

class ::Moderator
    @@token = nil
    @@token_expire_time = nil

    def self.is_token_expired?
        if @@token.nil?
            return false
        end

        cur_time = Time.new
        if cur_time > @@token_expire_time
            return false
        end

        true
    end

    def self.refresh_token?
        count = 0
        while !get_token?
            count += 1
            if count >= 10
                return false
            end
            sleep 1
        end
        true
    end

    def self.get_token?
        connection = Faraday.new do |f| 
            f.adapter FinalDestination::FaradayAdapter
        end
        auth_url = SiteSetting.sensitive_auth_url.sub(':project_name', SiteSetting.sensitive_project_name)
        auth_method = "POST".downcase.to_sym
        auth_body = { 
            auth: { 
                identity: {
                    methods: ["password"],
                    password: {
                        user: {
                            domain: {
                                name: ENV[SENSITIVE_DOMAIN_NAME]
                            },
                            name: ENV[SENSITIVE_NAME],
                            password: ENV[SENSITIVE_PASSWORD]
                        }
                    }
                }, 
                scope: {
                    project: {
                        id: SiteSetting.sensitive_check_project_id,
                        name: SiteSetting.sensitive_project_name
                    }
                }
            }
        }.to_json
        auth_body = JSON.parse(auth_body).to_s.gsub('=>', ':')
        auth_headers = { 'Content-Type' => 'application/json;charset=utf8' }
        response = connection.run_request(auth_method, auth_url, auth_body, auth_headers)
        log("sensitive token response: #{response.inspect}")

        if response.status == 201
            if SiteSetting.sensitive_auth_token_loc == "headers"
                result = response.headers
                @@token = result['x-subject-token']
                # @@token_expire_time = result[:token_expire_time]
                @@token_expire_time = Time.new + SiteSetting.sensitive_expire_time.to_i * 60 * 60
                true
            elsif SiteSetting.sensitive_auth_token_loc == "body"
                auth_json = JSON.parse(response.body)
                log("sensitive_token_json: #{auth_json}")

                result = {}
                if auth_json.present?
                    json_walk(result, auth_json, :token)
                    # json_walk(result, auth_json, :token_expire_time)
                end
                @@token = result[:token]
                # @@token_expire_time = result[:token_expire_time]
                @@token_expire_time = Time.new + SiteSetting.sensitive_expire_time.to_i * 60 * 60
                true
            end
        else
            false
        end
    end

    def self.log(info)
        Rails.logger.warn("Sensitive Check Debugging: #{info}") if SiteSetting.sensitive_debug_info
    end

    def self.text_request_body(text, event_type)
        body = {}
        body[:event_type] = event_type if event_type
        body[:data] = {text: text}.stringify_keys
        json_body = JSON.parse body.to_json
        json_body.to_s.gsub('=>', ':')
    end

    def self.json_walk(result, user_json, prop, custom_path: nil)
        path = custom_path || SiteSetting.public_send("sensitive_json_#{prop}_path")
        if path.present?
          #this.[].that is the same as this.that, allows for both this[0].that and this.[0].that path styles
          path = path.gsub(".[].", ".").gsub(".[", "[")
          segments = parse_segments(path)
          val = walk_path(user_json, segments)
          result[prop] = val if val.present?
        end
    end

    def self.parse_segments(path)
        segments = [+""]
        quoted = false
        escaped = false
    
        path.split("").each do |char|
            next_char_escaped = false
            if !escaped && (char == '"')
                quoted = !quoted
            elsif !escaped && !quoted && (char == '.')
                segments.append +""
            elsif !escaped && (char == '\\')
                next_char_escaped = true
            else
                segments.last << char
            end
            escaped = next_char_escaped
        end
    
        segments
    end

    def self.walk_path(fragment, segments, seg_index = 0)
        first_seg = segments[seg_index]
        return if first_seg.blank? || fragment.blank?
        return nil unless fragment.is_a?(Hash) || fragment.is_a?(Array)
        first_seg = segments[seg_index].scan(/([\d+])/).length > 0 ? first_seg.split("[")[0] : first_seg
        if fragment.is_a?(Hash)
            deref = fragment[first_seg] || fragment[first_seg.to_sym]
        else
            array_index = 0
            if (seg_index > 0)
                last_index = segments[seg_index - 1].scan(/([\d+])/).flatten() || [0]
                array_index = last_index.length > 0 ? last_index[0].to_i : 0
            end
            if fragment.any? && fragment.length >= array_index - 1
                deref = fragment[array_index][first_seg]
            else
                deref = nil
            end
        end
    
        if (deref.blank? || seg_index == segments.size - 1)
            deref
        else
            seg_index += 1
            walk_path(deref, segments, seg_index)
        end
    end

    def self.process_response(result)
        if result.nil?
            return nil, []
        end

        suggestion = result[:suggestion]
        if suggestion == SiteSetting.sensitive_block_exp and result[:hits].blank?
            return "block", []
        elsif suggestion == SiteSetting.sensitive_review_exp
            return "review", []
        elsif suggestion == SiteSetting.sensitive_pass_exp
            return "pass", []
        end

        hits = result[:hits].map do |seg|
            seg[SiteSetting.sensitive_seg_path_in_hits] if SiteSetting.sensitive_seg_path_in_hits
        end
        return "block", hits
    end

    # 功能：为文本请求moderate，返回请求结果
    # 输入：待检查文本, 事件类型
    # 输出：result --- {suggestion, hits}
    #       suggestion --- 处理建议，pass/block/review
    #       hits --- 命中词，[...]
    def self.request_for_text_moderation(text, event)
        if !is_token_expired?
            if !refresh_token?
                return nil
            end
        end

        connection = Faraday.new do |f| 
            f.adapter FinalDestination::FaradayAdapter
        end
        text_moderation_method = SiteSetting.sensitive_text_check_method.downcase.to_sym
        text_moderation_url = SiteSetting.sensitive_text_check_url.sub(':project_id', SiteSetting.sensitive_check_project_id).sub(':project_name', SiteSetting.sensitive_project_name)
        body = text_request_body(text, event)
        bearer_token = "#{@@token}"
        headers = { 'X-Auth-Token' => bearer_token, 'Content-Type' => 'application/json;charset=utf8' }
        log("request body: #{body}")

        response = connection.run_request(text_moderation_method, text_moderation_url, body, headers)
        log("text_check_response: #{response.inspect}")

        if response.status == 200
            text_check_json = JSON.parse(response.body)

            log("text_check_json: #{text_check_json}")

            result = {}
            if text_check_json.present?
                json_walk(result, text_check_json, :suggestion)
                json_walk(result, text_check_json, :hits)
                # json_walk(result, text_check_json, :label)
            end
            result
        else
            refresh_token?
            nil
        end
    end

    def self.should_block_txt?(text, event)
        response = request_for_text_moderation(text, event)
        process_response(response)
    end
end


### 使用继承原关注词的方式接入 ####
class WordModerator < WordWatcher
    # 存疑：对每种动作都使用moderator进行检查，相当于给每个动作加相同的词库
    # 功能：继承关注词匹配函数，在原始结果列表添加moderator检查结果
    # 输入：动作，是否对全部关注词进行匹配
    # 输出：命中词列表
    # TIPS：函数仅用来找到对应动作的命中词，不进行后续动作
    def word_matches_for_action?(action, event_type, all_matches: false)
        matched_words = []
        res = Moderator.new.request_for_text_moderation @raw, event_type
        
        matched_words.concat res, super(action, all_matches)
        return if matched_words.blank?

        matched_words.compact!
        matched_words.uniq!
        matched_words.sort!
        matched_words
    end

    # 功能：屏蔽关注词以及Moderator的命中词
    # 输入：html格式
    # 输出：nil
    # TIPS：会进行命中后的屏蔽处理
    def self.censor(html)
        doc = Nokogiri::HTML5::fragment(html)
        doc.traverse do |node|
            log("before censor: #{node.content}")
            segments = Moderator.new.request_for_text_moderation(node.content) if node.text?
            log("text_moderator_segments: #{segments}")
            segments.each do |segment|
                node.content = censor_text_with_regexp(node.content, segment) if node.text?
            end
            log("after censor: #{node.content}")
        end
        
        html = doc.to_html
        super(html)
    end

    # 功能：屏蔽关注词以及Moderator的命中词
    # 输入：待检查文本
    # 输出：nil
    # TIPS：会进行命中后的屏蔽处理
    def self.censor_text(text)
        return text if text.blank?
        log("before censor: #{text}")
        segments = Moderator.new.request_for_text_moderation(text)
        log("text_moderator_segments: #{segments}")
        segments.inject(text) do |txt, segment| 
            censor_text_with_regexp(txt, segment)
        end
        log("after censor: #{text}")
        super
    end
end


### 使用handler的方式接入标题和帖子新建内容检查 ###
class ModeratorValidator < ActiveModel::EachValidator
    def validate_each(record, attribute, value)
        # presence(record)

        return if record.acting_user.try(:staged?)
        return if record.acting_user.try(:admin?) && Discourse.static_doc_topic_ids.include?(record.topic_id)

        suggestion, matches = Moderator.should_block_txt? value, 'article'
        if suggestion.nil?
            key = "sensitive_check_failed"
            record.errors.add(attribute, I18n.t(key))
            return
        end
        if suggestion == "block"
            if matches.size == 0    
                key = "contains_sensitive_exp"
                record.errors.add(attribute, I18n.t(key))
            elsif matches.size == 1
                key = 'contains_sensitive_word'
                translation_args = { word: CGI.escapeHTML(matches[0]) }
                record.errors.add(attribute, I18n.t(key, translation_args))
            else
                key = 'contains_sensitive_words'
                translation_args = { words: CGI.escapeHTML(matches.join(', ')) }
                record.errors.add(attribute, I18n.t(key, translation_args))
            end
        elsif suggestion == "review"
            key = "sensitive_check_review"
            record.errors.add(attribute, key)
        end
    end

    def presence(post)
        unless options[:skip_topic]
            post.errors.add(:topic_id, :blank, **options) if post.topic_id.blank?
        end
    
        if post.new_record? && post.user_id.nil?
            post.errors.add(:user_id, :blank, **options)
        end
    end
end


NewPostManager.add_handler priority=9 do |manager|
    validator = ModeratorValidator.new(attributes: [:raw])
    post = Post.new(raw: "#{manager.args[:title]} #{manager.args[:raw]}")
    post.user = manager.user
    validator.validate(post) if !post.acting_user&.staged
    
    if post.errors[:raw].present?
        if post.errors[:raw].include? "sensitive_check_review"
            result = manager.enqueue(:sensitive_check_review)
            result
        else
            result = NewPostResult.new(:created_post, false)
            result.errors.add(:base, post.errors[:raw])
            result
        end
    else
        nil
    end
end
