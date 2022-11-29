

### 使用验证器的方式接入标题更新内容检查 ###
class TitleModeratorValidator < ActiveModel::EachValidator
    def validate_each(record, attribute, value)
        # presence(record)

        # return if record.acting_user.try(:staged?)
        # return if record.acting_user.try(:admin?) && Discourse.static_doc_topic_ids.include?(record.topic_id)

        suggestion, matches = Moderator.should_block_txt? value, 'title'
        if suggestion.nil?
            key = "sensitive_check_failed"
            record.errors.add(attribute, I18n.t(key))
            return
        end
        if suggestion == "block" or suggestion == "review"
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
        # elsif suggestion == "review"
        #     key = "sensitive_check_review"
        #     record.errors.add(attribute, key)
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
