package com.microservices.authservice.config;

import feign.RequestTemplate;
import feign.codec.Encoder;
import org.springframework.context.annotation.Bean;

import java.lang.reflect.Type;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class TokenClientFeignConfig {

    @Bean
    public Encoder feignFormEncoder() {
        return new FormUrlEncodedEncoder();
    }

    public static class FormUrlEncodedEncoder implements Encoder {
        @Override
        public void encode(Object object, Type bodyType, RequestTemplate template) {
            if (object instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> formParams = (Map<String, Object>) object;
                StringBuilder formBody = new StringBuilder();
                
                for (Map.Entry<String, Object> entry : formParams.entrySet()) {
                    if (formBody.length() > 0) {
                        formBody.append("&");
                    }
                    formBody.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                            .append("=")
                            .append(URLEncoder.encode(String.valueOf(entry.getValue()), StandardCharsets.UTF_8));
                }
                
                template.body(formBody.toString());
            }
        }
    }
}
